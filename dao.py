import sqlite3
from os.path import exists


def generate_insert_statement(data, table_name):
    # All dictionary keys must match column names in every case
    statement = f"INSERT INTO {table_name}("
    column_names = data.keys()
    values = data.values()
    statement += ",".join([col for col in column_names]) + ") VALUES("
    for value in values:
        if isinstance(value, str):
            value = value.replace("'", "''")
            statement += "'" + value + "',"
        else:
            statement += str(value) + ","
    statement = statement.rstrip(",")
    statement += ")"
    return statement


def destroy_database():
    import os

    os.remove("cutterdb")


def create_database():
    # SQLite will create any database file it was unable to find
    conn = sqlite3.connect("cutterdb")
    c = conn.cursor()

    # Make core audio files table
    c.execute(
        """
        CREATE TABLE IF NOT EXISTS audio_file
        ([audio_id] INTEGER PRIMARY KEY, 
        [audio_filename] TEXT,
        [audio_length] REAL,
        [audio_filesize_bytes] INTEGER,
        [audio_file_sha1] TEXT UNIQUE,
        [audio_filetime] TEXT,
        [audio_sample_rate] INTEGER,
        [audio_file_bitrate] INTEGER,
        [audio_sample_width] INTEGER,
        [audio_file_channels] INTEGER,
        [audio_segment_count] INTEGER,
        [audio_word_count] INTEGER,
        [audio_file_codec] TEXT)
        """
    )

    # Make audio segments table
    c.execute(
        """
        CREATE TABLE IF NOT EXISTS audio_segment
        ([seg_id] INTEGER PRIMARY KEY, 
        [audio_id] INTEGER,
        [seg_length] REAL,
        [tr_id] INTEGER,
        [sub_id] INTEGER)
        """
    )

    # Make audio transcriptions table
    c.execute(
        """
        CREATE TABLE IF NOT EXISTS transcript
        ([tr_id] INTEGER PRIMARY KEY, 
        [audio_id] INTEGER,
        [tr_text] TEXT,
        [tr_sha1] TEXT,
        [tr_length] INTEGER,
        [word_count] INTEGER)
        """
    )

    # Make words table
    # {'word': ' You', 'start': 0.0, 'end': 0.14, 'probability': 0.23748593032360077}
    c.execute(
        """
        CREATE TABLE IF NOT EXISTS word_instance
        ([wi_id] INTEGER PRIMARY KEY,
        [word_id] INTEGER,
        [seg_id] INTEGER,
        [tr_id] INTEGER,
        [ident_id] INTEGER,
        [word] TEXT,
        [start] REAL,
        [end] REAL,
        [probability] REAL)
    """
    )

    # Make audio segment identifier table
    c.execute(
        """
        CREATE TABLE IF NOT EXISTS identifier
        ([ident_id] INTEGER PRIMARY KEY, 
        [audio_id] INTEGER,
        [seg_id] INTEGER,
        [seg_length] REAL,
        [total_energy] REAL,
        [bin_count] INTEGER,
        [ident_sha1] TEXT UNIQUE,
        [ident_text] TEXT,
        [tr_hash] TEXT, 
        [tr_id] INTEGER,
        [tr_length] INTEGER)
        """
    )

    # Make word audio identifier table
    c.execute(
        """
        CREATE TABLE IF NOT EXISTS word_identifier
        ([word_id] INTEGER PRIMARY KEY, 
        [audio_id] INTEGER,
        [seg_id] INTEGER,
        [word_length] REAL,
        [total_energy] REAL,
        [bin_count] INTEGER,
        [ident_sha1] TEXT,
        [ident_text] TEXT,
        [word_hash] TEXT, 
        [tr_id] INTEGER,
        [word_char_length] INTEGER)
            """
    )

    conn.commit()
    conn.close()
    print("Created a brand-new cutter database!")


class CutterDAO:
    def __init__(self):
        if not exists("cutterdb"):
            create_database()
        self.conn = sqlite3.connect("cutterdb")
        self.cursor = self.conn.cursor()

    def close(self):
        self.conn.close()

    def commit(self):
        self.conn.commit()

    def rollback(self):
        self.conn.rollback()

    def begin_transaction(self):
        self.cursor.execute("BEGIN TRANSACTION;")

    def fetch_file_match(self, sha1):
        statement = (
            f"""select count(*) from audio_file where audio_file_sha1='{sha1}'"""
        )
        data = self.cursor.execute(statement)
        result = data.fetchall()
        return result

    def fetch_exact_transcript_matches_count(self, tr_text, sha1):
        tr_text = tr_text.replace("'", "''")
        statement = f"""select count(*) from transcript where tr_text='{tr_text}' or tr_text like '%{tr_text}%'"""
        data = self.cursor.execute(statement)
        result = data.fetchone()
        return result

    def fetch_exact_transcript_matches(self, tr_text, sha1):
        tr_text = tr_text.replace("'", "''")
        statement = f"""select distinct i.ident_text, tr.tr_id from transcript tr join identifier i on i.tr_id=tr.tr_id where tr.tr_text='{tr_text}' or tr_text like '%{tr_text}%'"""
        data = self.cursor.execute(statement)
        result = data.fetchall()
        return result

    def fetch_word_sequence(self, tr_id):
        statement = f"""select distinct 
        word, start, end from word_instance wi 
        join transcript tr on tr.tr_id = wi.tr_id
        where tr.tr_id = {tr_id}
        order by start;"""
        data = self.cursor.execute(statement)
        result = data.fetchall()
        return result

    def insert_audio_file(self, data: dict):
        insert_statement = generate_insert_statement(data, "audio_file")
        self.cursor.execute(insert_statement)
        print(f"Inserted an audio file: {data['audio_filename']} into DB")
        return self.cursor.lastrowid

    def insert_segment_count(self, segment_count, id):
        statement = f"UPDATE audio_file set audio_segment_count = {segment_count} WHERE audio_id={id}"
        self.cursor.execute(statement)
        print("Updated a segment count!")

    def insert_transcript(self, transcript_data):
        insert_statement = generate_insert_statement(transcript_data, "transcript")
        self.cursor.execute(insert_statement)
        print("Inserted a transcript!")
        return self.cursor.lastrowid

    def insert_data(self, data, table):
        insert_statement = generate_insert_statement(data, table)
        self.cursor.execute(insert_statement)
        print(f"Inserted {table}!")
        return self.cursor.lastrowid

    def insert_segment(self, segment_data):
        insert_statement = generate_insert_statement(segment_data, "audio_segment")
        self.cursor.execute(insert_statement)
        print("Inserted an audio segment!")
        return self.cursor.lastrowid

    def insert_identifier(self, identifier_data):
        insert_statement = generate_insert_statement(identifier_data, "identifier")
        self.cursor.execute(insert_statement)
        print("Inserted an audio identifier!")
        return self.cursor.lastrowid

    def insert_word_identifier(self, identifier_data):
        insert_statement = generate_insert_statement(identifier_data, "word_identifier")
        self.cursor.execute(insert_statement)
        print("Inserted a word identifier!")
        return self.cursor.lastrowid

    def insert_word_instance(self, word_data: dict):
        insert_statement = generate_insert_statement(word_data, "word_instance")
        self.cursor.execute(insert_statement)
        return self.cursor.lastrowid

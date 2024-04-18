import time
import random
import json
import logging as log
import psycopg2
from psycopg2.extensions import ISOLATION_LEVEL_AUTOCOMMIT
from constants import DB_NAME, DB_HOST, DB_PORT, DB_USER, DB_PASS


def generate_insert_statement(data, table_name):
    """
    All dictionary keys must match column names in every case.
    """
    statement = f"INSERT INTO {table_name}("
    column_names = data.keys()
    values = data.values()
    statement += ",".join(list(column_names)) + ") VALUES("
    for value in values:
        if isinstance(value, str):
            value = value.replace("'", "''")
            statement += "'" + value + "',"
        else:
            statement += str(value) + ","
    statement = statement.rstrip(",")
    statement += ")"
    return statement


class MalaDAO:
    """
    A class for handling all DB transactions.
    """
    def __init__(self):
        if DB_HOST == '/var/run/postgresql':
            self.conn = psycopg2.connect(
                host=DB_HOST,
                dbname=DB_NAME,
                user=DB_USER,
                password=DB_PASS,
            )
        else:
            self.conn = psycopg2.connect(
                host=DB_HOST,
                port=DB_PORT,
                dbname=DB_NAME,
                user=DB_USER,
                password=DB_PASS,
            )
        self.conn.set_isolation_level(ISOLATION_LEVEL_AUTOCOMMIT)
        self.cursor = self.conn.cursor()


    def destroy(self):
        """Close the DB connection."""
        self.cursor.close()
        self.conn.close()


    def get_file_rowcount(self, file_id, table_name):
        """Return the rowcount for a sample in a given table."""
        sql = f"select count(*) from {table_name} where id_file = {file_id};"
        self.cursor.execute(sql)
        result = self.cursor.fetchone()
        return result[0]


    def search_package(self, package_name):
        """Search for packages by name."""
        sql = f"select * from t_package where basename = '{package_name}';"
        self.cursor.execute(sql)
        result = self.cursor.fetchall()
        return result


    def get_via_sha256(self, sha256):
        """Get a file id by SHA256. If None, the file is unknown."""
        statement = f"select id from t_file where sha256 = '{sha256}' limit 1;"
        self.cursor.execute(statement)
        try:
            result = self.cursor.fetchone()
            if result is None:
                return None
        except Exception as e:
            log.debug(e)
            return None
        return result[0]


    def insert_statement_returning_id(self, insert_statement):
        """Insert data and return its new id."""
        inserted_id = -1
        try:
            self.cursor.execute(insert_statement)
            result = self.cursor.fetchone()
            if not result:
                log.debug(f"Result was none for insert statement: {insert_statement}")
                return -1
            inserted_id = result[0]
        except Exception as e:
            log.debug(repr(e))
            log.debug("Error inserting data in MalaDao.")
            log.debug(insert_statement)
        return inserted_id


    def insert_data_returning_id(self, data:dict, table_name):
        """Generate the insert statement and execute it, returning the id."""
        insert_statement = generate_insert_statement(data, table_name) + "returning id;"
        this_id = self.insert_statement_returning_id(insert_statement)
        return this_id


    def get_package_file_rowcount(self,  package_name):
        sql = f"select count(distinct tf.id) from t_file tf where path like '%/{package_name}/%'"
        self.cursor.execute(sql)
        try:
            result = self.cursor.fetchone()
            if result is None:
                return None
        except Exception as e:
            log.debug(e)
            return None
        return result[0]


    def associate_file_to_execution(self, file_id, execution_id):
        """Link each sample to the execution where we saw it.
        This does not give us a precise timestamp of ingestion for every sample,
        but it does give an approximate ingestion date in the worst case.
        """
        sql = "insert into t_file_ingest(id_file, id_execution) values (%s, %s)"
        self.cursor.execute(sql, (file_id, execution_id))


    def insert_execution(self, data: dict):
        """
        Insert a record of this mala run in the DB.
        """
        inserted_id = self.insert_data_returning_id(data, 't_executions')
        return inserted_id


    def insert_package(self, data: dict):
        """
        Insert one malware archive into the DB.
        """
        inserted_id = self.insert_data_returning_id(data, "t_package")
        return inserted_id


    def insert_malware_file(self, data: dict):
        """
        Insert one malware file into the DB."""
        inserted_id = self.insert_data_returning_id(data, "t_file")
        return inserted_id


    def insert_mala_strings(self, json_data, file_id):
        """
        Use a custom Rust binary to replicate using strings and filtering the outputs in python.
        Significantly faster than binutils strings (44 samples/s -> 54).
        """
        if len(json_data) == 0:
            return
        json_data = json_data.split("\n")
        strings = []
        scores = []
        addresses = []
        for string_inst in json_data[:-1]:
            string_instance = json.loads(string_inst)
            strings.append(string_instance['string'])
            scores.append(string_instance['score'])
            addresses.append(string_instance['position'])
        self.insert_string_instances(strings, scores, addresses, file_id)


    def insert_string_instances(self, strings, scores, addresses, file_id):
        """
        Databases do not like this function, but they deserve it. /s
        Just retry forever in case of deadlocks.
        Deadlocks are minimised by batching operations. Deadlocks happen
        because the t_strings table has a unique constraint on 'value',
        so if a new string is present in two samples' output at once, and both
        arrays are being inserted, there is a conflict between the two transactions.
        """
        success = False

        if len(strings) == 0:
            print(f"No strings to process for file {file_id}")
            return
        num_strings = len(strings)
        done_count = 0
        step_size = 256
        while not success:
            try:
                self.cursor.callproc(
                    # The insert_strings procedure is idempotent
                    "insert_strings", 
                    (
                        strings[done_count:done_count+step_size],
                        scores[done_count:done_count+step_size])
                )
                done_count += step_size
                if done_count >= num_strings:
                    success = True
            except Exception as e:
                log.debug(e)
                time.sleep(random.randint(2, 9) * 1.0 / 10.0)

        try:
            self.cursor.callproc(
                    "insert_string_instances", 
                    (
                        strings,
                        int(file_id),
                        addresses)
                )
        except Exception as e:
            print("CRASHED IN DAO.insert_string_instances")
            print(e)


    def insert_exif_json(self, exif_data, file_id):
        """
        Exiftool supports JSON output. Creating a column for each tag
        it supports is not an option, so just sure tags and corresponding
        values in the DB.
        """
        values = []
        sql_statement = (
            "INSERT INTO t_exiftool (tag, content, id_file) VALUES (%s, %s, %s)"
        )

        for key, value in exif_data.items():
            entry = (key, str(value), file_id)
            values.append(entry)

        self.cursor.executemany(sql_statement, values)


    def insert_tlsh_json(self, tlsh_data, file_id):
        """
        TLSH output in JSON format, which also provides a SHA256 hash,
        we don't need as we have it already in t_file.
        """
        values = [tlsh_data['digests'][0]['tlsh'], file_id]
        sql_statement = (
            "INSERT INTO t_tlsh (tlsh_hash, id_file) VALUES (%s, %s)"
        )
        self.cursor.execute(sql_statement, values)


    def insert_ssdeep_hash(self, ssdeep_data, file_id):
        """
        Store the ssdeep hash of the sample.
        """
        ssdeep_lines = ssdeep_data.split('\n')
        ssdeep_hash = ssdeep_lines[1].split(',')[0]
        values = [ssdeep_hash, file_id]
        sql_statement = (
            "INSERT INTO t_ssdeep (ssdeep_hash, id_file) VALUES (%s, %s)"
        )
        self.cursor.execute(sql_statement, values)


    def get_fpath_from_id(self, file_id):
        """
        Get the path of the sample. If you have a defined table structure, you can use this
        after ingestion to infer which package it came from later, for example 
            `if path contains('InTheWild.0013'):...` 
        If you ensure the file is still present and are not deleting samples, then you can 
        directly access the sample at this path.
        """
        sql = f"select path from t_file where id = {file_id}"
        self.cursor.execute(sql)
        result = self.cursor.fetchone()
        return result[0]


    def get_no_strings_files(self):
        """
        Get all file IDs which don't have any strings info.
        As getting distinct file ids requires a sequential scan,
        it's efficient to just keep the smaller list of files in memory once.
        """
        sql = "select distinct id from t_file where id not in (select distinct \
            id_file from t_stringinstance);"
        self.cursor.execute(sql)
        return self.cursor.fetchall()


    def insert_diec_json(self, diec_data, file_id):
        """
        Parse the JSON output of diec and store it in three tables:
        - t_diec: information from the deep section scan
        - t_diec_ent: entropy information about the sample's sectors
        - t_diec_meta: entropy information about the sample's overall entropy
        """
        values = []
        if 'detects' in diec_data.keys():
            # Deep scan
            results = diec_data['detects'][0]
            if 'values' in results.keys():
                results = results['values']
                sql_statement = (
                    "INSERT INTO t_diec (info, name, string, type, version, \
                        id_file) VALUES (%s, %s, %s, %s, %s, %s)"
                )
                for struct in results:
                    struct['id_file'] = file_id
                    sql = generate_insert_statement(struct, 't_diec')
                    self.cursor.execute(sql)
            else:
                sql_statement = (
                    f"INSERT INTO t_diec (info, name, string, type, version, id_file) VALUES \
                        ('broken', 'broken', '{results['string']}', 'broken', 'broken', {file_id})"
                )
                self.cursor.execute(sql_statement)
        elif 'records' in diec_data.keys():
            # Entropy scan
            results = diec_data['records']
            sql_statement = (
                "INSERT INTO t_diec_ent (entropy, name, s_offset, size, status, id_file)\
                     VALUES (%s, %s, %s, %s, %s, %s)"
            )
            for struct in results:
                entry = (
                    struct['entropy'],
                    struct['name'],
                    struct['offset'],
                    struct['size'],
                    struct['status'],
                    file_id
                    )
                values.append(entry)
            meta_statement = f"INSERT INTO t_diec_meta (entropy, status, id_file)\
                 VALUES ({diec_data['total']}, '{diec_data['status']}', {file_id})"
            self.cursor.executemany(sql_statement, values)
            self.cursor.execute(meta_statement)

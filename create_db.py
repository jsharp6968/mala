"""
A module of functions for creating the DB structure of mala.
If you trigger the setup() function, you will create everything needed
to run mala.
"""
import psycopg2
from psycopg2.extensions import ISOLATION_LEVEL_AUTOCOMMIT
from constants import DB_NAME, DB_USER, DB_PASS, DB_HOST


def connect():
    """
    Connect to the database using the parameters specified in constants.py.
    """
    conn = psycopg2.connect(
        host=DB_HOST, dbname=DB_NAME, user=DB_USER, password=DB_PASS
    )
    conn.set_isolation_level(ISOLATION_LEVEL_AUTOCOMMIT)
    return conn


def execute_sql(conn, sql):
    """
    Execute an SQL statent. Cursor will be closed after.
    """
    with conn.cursor() as cur:
        cur.execute(sql)


def select_sql(conn, sql):
    """
    Execute a SELECT statement in SQL. Cursor will be closed after.
    """
    with conn.cursor() as cur:
        cur.execute(sql)
        rows = cur.fetchall()
        return rows


def setup():
    """
    Connect to the database and ensure every table and 
    stored procedure exists.
    """
    setup_conn = connect()
    create_file_table(setup_conn)
    create_exiftool_table(setup_conn)
    create_strings_table(setup_conn)
    create_stringinstance_table(setup_conn)
    create_diec_ent_table(setup_conn)
    create_diec_meta_table(setup_conn)
    create_diec_table(setup_conn)
    create_tlsh_table(setup_conn)
    create_string_insert_sp(setup_conn)
    create_string_instance_sp(setup_conn)
    create_ssdeep_table(setup_conn)
    create_packages_table(setup_conn)
    create_file_ingest_table(setup_conn)
    create_executions_table(setup_conn)
    setup_conn.close()
    print("Completed setup!")


def create_table(conn, table_name, table_cols:list):
    """
    Strings needs a Bigserial. I hit 2.147 Bn strings at ~950k samples.
    Bigserial goes to the moon.
    """
    sql = f"CREATE TABLE IF NOT EXISTS {table_name} (id bigserial primary key, "
    sql += ", ".join(table_cols)
    sql += ");"
    execute_sql(conn, sql)


def create_exiftool_table(conn):
    """
    Table for exiftool data.
    """
    columns = [
        "id_file bigint", 
        "tag text", 
        "content text",
        "FOREIGN KEY (id_file) REFERENCES t_file(id)",
        ]
    create_table(conn, 't_exiftool', columns)


def create_file_table(conn):
    """
    Apparently, CHAR is more efficient than VARCHAR or text for fixed-length strings.
    """
    columns = [
        "md5 CHAR(32)",
        "sha256 CHAR(64) UNIQUE",
        "sha1 CHAR(40)",
        "basename text",
        "path text",
        "fsize integer",
    ]
    create_table(conn, 't_file', columns)


def create_packages_table(conn):
    """
    A table for ingested archives from sources like VXUG and Virusshare etc.
    """
    columns = [
        "md5 CHAR(32) unique",
        "basename text",
        "path text",
        "fsize bigint",
        "date_ingested timestamp without time zone",
        "fcount integer",
    ]
    create_table(conn, 't_package', columns)


def create_file_ingest_table(conn):
    """
    A table for holding relations between individual samples and mala executions.
    """
    columns = [
        "id_file bigint",
        "id_execution bigint",
    ]
    create_table(conn, 't_file_ingest', columns)


def create_executions_table(conn):
    """
    A table for recording each execution of mala.
    Also provides the basis for linking files to executions.
    Useful for tracking performance over time.
    """
    columns = [
        "exec_uuid CHAR(36) unique",
        "cmdline text",
        "fcount integer",
        "start_time timestamp without time zone",
        "finish_time timestamp without time zone",
        "toolchain text",
        "thread_limit integer",
        "shr_cutoff integer",
        "fcount_sanity integer",
        "handled_count integer",
        "verified_count integer"
    ]
    create_table(conn, 't_executions', columns)


def create_strings_table(conn):
    """
    Table for strings. There is a uniqueness constraint on
    the value column, and an integer score.
    """
    columns = [
        "value text unique",
        "score integer"
    ]
    create_table(conn, 't_strings', columns)


def create_stringinstance_table(conn):
    """
    Table for holding references between strings and files.
    For each reference, it holds the address at which the string was found
    inside the sample.
    """
    columns = [
        "id_file bigint", 
        "id_string bigint", 
        "address integer",
        "FOREIGN KEY (id_file) REFERENCES t_file(id)",
        "FOREIGN KEY (id_string) REFERENCES t_strings(id)",
        ]
    create_table(conn, 't_stringinstance', columns)


def create_tlsh_table(conn):
    """
    Table holding TLSH hashes for samples.
    As there are some old TLSH hashes which are a shorter length, we use a 
    VARCHAR instead of CHAR, because this table is super fast anyway, and we
    can support ingesting old hashes too.
    """
    columns = [
        "id_file bigint", 
        "tlsh_hash varchar(72)",
        "FOREIGN KEY (id_file) REFERENCES t_file(id)",
        ]
    create_table(conn, 't_tlsh', columns)


def create_ssdeep_table(conn):
    """
    Table for holding ssdeep hashes for files. Can hold up to 1480 chars in the hash.
    """
    columns = [
        "id_file bigint", 
        "ssdeep_hash varchar(1480)", 
        "FOREIGN KEY (id_file) REFERENCES t_file(id)",
        ]
    create_table(conn, 't_ssdeep', columns)


def create_diec_table(conn):
    """
    A table for holding the results of diec deep scans.
    """
    columns = [
        "id_file bigint", 
        "info text",
        "name text",
        "string text",
        "type text",
        "version text",
        "FOREIGN KEY (id_file) REFERENCES t_file(id)",
        ]
    create_table(conn, 't_diec', columns)


def create_diec_ent_table(conn):
    """
    Table for holding the results of running an entropy scan with diec.
    """
    columns = [
        "id_file bigint", 
        "entropy decimal(10, 8)",
        "name text",
        "s_offset bigint",
        "size bigint",
        "status text",
        "FOREIGN KEY (id_file) REFERENCES t_file(id)",
        ]
    create_table(conn, 't_diec_ent', columns)


def create_diec_meta_table(conn):
    """
    Table for holding the entropy scan results of the file overall.
    """
    columns = [
        "id_file bigint", 
        "entropy decimal(10, 8)",
        "status text",
        "FOREIGN KEY (id_file) REFERENCES t_file(id)",
        ]
    create_table(conn, 't_diec_meta', columns)


def create_string_insert_sp(conn):
    """
    Create the stored procedure for inserting strings with their scores.
    """
    sql = """CREATE OR REPLACE FUNCTION insert_strings(arr_strings TEXT[], arr_scores INTEGER[])
RETURNS VOID AS $$
BEGIN
    INSERT INTO t_strings (value, score)
    SELECT unnest(arr_strings), unnest(arr_scores)
    ON CONFLICT (value) DO NOTHING;
END;
$$ LANGUAGE plpgsql;
    """
    execute_sql(conn, sql)


def create_string_instance_sp(conn):
    """
    Create the stored procedure for storing references to strings, and their addresses in decimal.
    """
    sql = """CREATE OR REPLACE FUNCTION insert_string_instances(arr_strings TEXT[], \
        file_id_val INTEGER, arr_addresses INTEGER[])
RETURNS VOID AS $$
BEGIN
    INSERT INTO t_stringinstance (id_string, id_file, address)
    SELECT t.id, file_id_val, a.address
    FROM unnest(arr_strings) WITH ORDINALITY AS v(value, ord)
    JOIN t_strings t ON t.value = v.value
    JOIN unnest(arr_addresses) WITH ORDINALITY AS a(address, ord) ON v.ord = a.ord;
END;
$$ LANGUAGE plpgsql;
    """
    execute_sql(conn, sql)

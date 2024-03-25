import psycopg2
from psycopg2 import sql
from psycopg2.extensions import ISOLATION_LEVEL_AUTOCOMMIT
from constants import DB_NAME, DB_USER, DB_PASS


def create_table_from_json(table_name, json_dict):
    type_mapping = {
        "int": "INTEGER",
        "float": "REAL",
        "str": "TEXT",
        "bool": "BOOLEAN",
    }

    sql = f"CREATE TABLE {table_name} (id integer primary key, "

    columns = []
    for column, value in json_dict.items():
        data_type = type(value).__name__
        sql_type = type_mapping.get(
            data_type, "TEXT"
        )  # Default to TEXT if type is unknown
        columns.append(f"{column} {sql_type}")

    sql += ", ".join(columns)
    sql += ");"
    return sql


def connect():
    conn = psycopg2.connect(
        host="/var/run/postgresql", dbname=DB_NAME, user=DB_USER, password=DB_PASS
    )
    conn.set_isolation_level(ISOLATION_LEVEL_AUTOCOMMIT)
    return conn


def execute_sql(conn, sql):
    with conn.cursor() as cur:
        cur.execute(sql)
        conn.commit()


def select_sql(conn, sql):
    with conn.cursor() as cur:
        cur.execute(sql)
        rows = cur.fetchall()
        cur.close()
        return rows


def setup():
    setup_conn = connect()
    
    create_exiftool_table(setup_conn)
    create_strings_table(setup_conn)
    create_file_table(setup_conn)
    create_stringinstance_table(setup_conn)
    create_string_ingestion_stored_procedure(setup_conn)
    create_string_ingestion_stored_procedure_multi(setup_conn)
    create_diec_ent_table(setup_conn)
    create_diec_meta_table(setup_conn)
    create_diec_table(setup_conn)
    create_tlsh_table(setup_conn)
    create_string_ingestion_dev_sp_multi(setup_conn)
    create_string_insert_sp(setup_conn)
    create_string_instance_sp(setup_conn)
    create_ssdeep_table(setup_conn)
    print("Completed setup!")

def check_table_exists(conn, table_name):
    sql = f"""SELECT EXISTS (
   SELECT FROM pg_catalog.pg_tables 
   WHERE  schemaname != 'pg_catalog' AND 
          schemaname != 'information_schema' AND 
          tablename = '{table_name}'
);"""
    select_sql(conn, sql)


def check_existing_file(sha256):
    conn = connect()
    sql = f"select id from t_file where sha256 = ’{sha256}’ limit 1;"
    row = select_sql(conn, sql)[0]
    print(row)

def create_tool_table(conn, table_name, table_cols:list):
    sql = f"CREATE TABLE IF NOT EXISTS {table_name} (id serial primary key, "
    sql += ", ".join(columns)
    sql += ");"
    execute_sql(conn, sql)


def create_exiftool_table(conn):
    sql = "CREATE TABLE IF NOT EXISTS t_exiftool (id serial primary key, "
    columns = ["id_file bigint", "tag text", "content text"]
    sql += ", ".join(columns)
    sql += ");"
    execute_sql(conn, sql)


def create_file_table(conn):
    """
    Apparently, CHAR is more efficient than VARCHAR or text for fixed-length strings.
    """
    sql = "CREATE TABLE IF NOT EXISTS t_file (id serial primary key, "
    columns = [
        "md5 CHAR(32)",
        "sha256 CHAR(64) UNIQUE",
        "sha1 CHAR(40)",
        "basename text",
        "path text",
        "fsize integer",
    ]
    sql += ", ".join(columns)
    sql += ");"
    execute_sql(conn, sql)


def create_strings_table(conn):
    sql = "CREATE TABLE IF NOT EXISTS t_strings (id serial primary key, "
    columns = [
        "value text unique",
        "score integer"
    ]
    sql += ", ".join(columns)
    sql += ");"
    execute_sql(conn, sql)


def create_stringinstance_table(conn):
    sql = "CREATE TABLE IF NOT EXISTS t_stringinstance (id serial primary key, "
    columns = ["id_file bigint", "id_string bigint", "address bytea"]
    sql += ", ".join(columns)
    sql += ");"
    execute_sql(conn, sql)

def create_tlsh_table(conn):
    sql = "CREATE TABLE IF NOT EXISTS t_tlsh (id serial primary key, "
    columns = ["id_file bigint", "tlsh_hash varchar(72)"]
    sql += ", ".join(columns)
    sql += ");"
    execute_sql(conn, sql)

def create_ssdeep_table(conn):
    sql = "CREATE TABLE IF NOT EXISTS t_ssdeep (id serial primary key, "
    columns = ["id_file bigint", "ssdeep_hash varchar(1480)"]
    sql += ", ".join(columns)
    sql += ");"
    execute_sql(conn, sql)

def create_diec_table(conn):
    sql = "CREATE TABLE IF NOT EXISTS t_diec (id serial primary key, "
    columns = [
        "id_file bigint", 
        "info text",
        "name text",
        "string text",
        "type text",
        "version text"
        ]
    sql += ", ".join(columns)
    sql += ");"
    execute_sql(conn, sql)

def create_diec_ent_table(conn):
    sql = "CREATE TABLE IF NOT EXISTS t_diec_ent (id serial primary key, "
    columns = [
        "id_file bigint", 
        "entropy decimal(10, 8)",
        "name text",
        "s_offset bigint",
        "size bigint",
        "status text"
        ]
    sql += ", ".join(columns)
    sql += ");"
    execute_sql(conn, sql)

def create_diec_meta_table(conn):
    sql = "CREATE TABLE IF NOT EXISTS t_diec_meta (id serial primary key, "
    columns = [
        "id_file bigint", 
        "entropy decimal(10, 8)",
        "status text"
        ]
    sql += ", ".join(columns)
    sql += ");"
    execute_sql(conn, sql)


def create_string_ingestion_stored_procedure(conn):
    sql = """CREATE OR REPLACE FUNCTION insert_string_and_instance(string_val TEXT, file_id_val INTEGER)
RETURNS VOID AS $$
DECLARE
    v_string_id BIGINT;
BEGIN
    INSERT INTO t_strings (value) VALUES (string_val) ON CONFLICT (value) DO NOTHING;
    SELECT id INTO v_string_id FROM t_strings WHERE value = string_val;
    
    INSERT INTO t_stringinstance (id_string, id_file) VALUES (v_string_id, file_id_val);
END;
$$ LANGUAGE plpgsql;"""
    execute_sql(conn, sql)


def create_string_ingestion_stored_procedure_multi(conn):
    """
    Create a stored procedure which takes a newline-separated list of strings
    and inserts them into the strings table, ignoring existing entries to permit the
    uniqueness constraint, then inserting the reference from file <id> string in t_stringinstance.
    """
    sql = """CREATE OR REPLACE FUNCTION insert_string_and_instance_multi(string_val TEXT, file_id_val INTEGER)
RETURNS VOID AS $$
DECLARE
    arr_strings TEXT[];
BEGIN
    arr_strings := string_to_array(string_val, E'\n'); -- Split input string by newline

    -- Batch insert into t_strings
    INSERT INTO t_strings (value)
    SELECT unnest(arr_strings)
    ON CONFLICT (value) DO NOTHING;

    -- Insert into t_stringinstance
    INSERT INTO t_stringinstance (id_string, id_file)
    SELECT s.id, file_id_val
    FROM unnest(arr_strings) AS v(value)
    JOIN t_strings s ON s.value = v.value;
END;
$$ LANGUAGE plpgsql;

"""
    execute_sql(conn, sql)

def create_string_ingestion_dev_sp_multi(conn):
    sql = """CREATE OR REPLACE FUNCTION insert_string_and_instance_dev(arr_strings TEXT[], arr_scores INTEGER[], file_id_val INTEGER, arr_addresses TEXT[])
RETURNS VOID AS $$
BEGIN
    -- Insert new strings into t_strings, ignoring conflicts
    WITH ins AS (
        INSERT INTO t_strings (value, score)
        SELECT unnest(arr_strings), unnest(arr_scores)
        ON CONFLICT (value) DO NOTHING
        RETURNING id, value
    ),
    indexed_values AS (
        SELECT value, generate_series(1, array_length(arr_strings, 1)) AS idx
        FROM unnest(arr_strings) AS value
    ),
    -- Fetch ids for all strings, whether newly inserted or existing
    all_strings AS (
        SELECT t.id, t.value, iv.idx
        FROM t_strings t
        JOIN indexed_values iv ON t.value = iv.value
    ),
    indexed_addresses AS (
        SELECT unnest(arr_addresses) AS address, generate_series(1, array_length(arr_addresses, 1)) AS idx
    )
    -- Insert into t_stringinstance, ensuring correct string-address association
    INSERT INTO t_stringinstance (id_string, id_file, address)
    SELECT all_strings.id, file_id_val, decode(indexed_addresses.address, 'hex')
    FROM all_strings
    JOIN indexed_addresses ON all_strings.idx = indexed_addresses.idx;
END;
$$ LANGUAGE plpgsql;

"""
    execute_sql(conn, sql)

def create_string_insert_sp(conn):
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
    sql = """CREATE OR REPLACE FUNCTION insert_string_instances(arr_strings TEXT[], file_id_val INTEGER, arr_addresses TEXT[])
RETURNS VOID AS $$
BEGIN
    INSERT INTO t_stringinstance (id_string, id_file, address)
    SELECT t.id, file_id_val, decode(a.address, 'hex')
    FROM unnest(arr_strings) WITH ORDINALITY AS v(value, ord)
    JOIN t_strings t ON t.value = v.value
    JOIN unnest(arr_addresses) WITH ORDINALITY AS a(address, ord) ON v.ord = a.ord;
END;
$$ LANGUAGE plpgsql;

    """
    execute_sql(conn, sql)
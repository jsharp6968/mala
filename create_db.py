import psycopg2
from psycopg2.extensions import ISOLATION_LEVEL_AUTOCOMMIT
from constants import DB_NAME, DB_USER, DB_PASS, DB_HOST


def connect():
    conn = psycopg2.connect(
        host=DB_HOST, dbname=DB_NAME, user=DB_USER, password=DB_PASS
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
    columns = [
        "id_file bigint", 
        "tag text", 
        "content text",
        #"FOREIGN KEY (id_file) REFERENCES t_file(id)",
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


def create_strings_table(conn):
    columns = [
        "value text unique",
        "score integer"
    ]
    create_table(conn, 't_strings', columns)


def create_stringinstance_table(conn):
    columns = [
        "id_file bigint", 
        "id_string bigint", 
        "address integer",
        #"FOREIGN KEY (id_file) REFERENCES t_file(id)",
        #"FOREIGN KEY (id_string) REFERENCES t_strings(id)",
        ]
    create_table(conn, 't_stringinstance', columns)


def create_tlsh_table(conn):
    columns = [
        "id_file bigint", 
        "tlsh_hash varchar(72)",
        #"FOREIGN KEY (id_file) REFERENCES t_file(id)",
        ]
    create_table(conn, 't_stringinstance', columns)


def create_ssdeep_table(conn):
    columns = [
        "id_file bigint", 
        "ssdeep_hash varchar(1480)", 
        #"FOREIGN KEY (id_file) REFERENCES t_file(id)",
        ]
    create_table(conn, 't_stringinstance', columns)


def create_diec_table(conn):
    columns = [
        "id_file bigint", 
        "info text",
        "name text",
        "string text",
        "type text",
        "version text",
        #"FOREIGN KEY (id_file) REFERENCES t_file(id)",
        ]
    create_table(conn, 't_diec', columns)


def create_diec_ent_table(conn):
    columns = [
        "id_file bigint", 
        "entropy decimal(10, 8)",
        "name text",
        "s_offset bigint",
        "size bigint",
        "status text",
        #"FOREIGN KEY (id_file) REFERENCES t_file(id)",
        ]
    create_table(conn, 't_diec_ent', columns)


def create_diec_meta_table(conn):
    columns = [
        "id_file bigint", 
        "entropy decimal(10, 8)",
        "status text",
        #"FOREIGN KEY (id_file) REFERENCES t_file(id)",
        ]
    create_table(conn, 't_diec_ent', columns)


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


"""
Constants for mala.

DB_NAME: The name of the DB Schema you want to use
DB_HOST: Your DB host (localhost most likely)
DB_PORT: Defaults to 5432
DB_USER: Defaults to mala_user, which comes from running setup.sh
DB_PASS: Is generated and stored in the MALA_DB_PASS env var by
        setup.sh

THREAD_LIMIT: Defaults to using all CPU cores
MAX_STRING_CHAR_LIMIT: Defaults to 2600
FILE_HASH_BUFFER_SIZE: How many bytes to buffer when hashing files
SHR_CUTOFF: Minimum string-readability score
MALA_OUTPUT_DIR: Unused
TOOLCHAIN: A list of tools cmdlines as strings
TOOL_TABLES: A dictionary map of tools : tables
EMERGENT: The string of characters ordered by most frequent first 
        which is used to evaluate the readability of each string.
"""
import os
DB_NAME = "mala"
DB_HOST = "/var/run/postgresql"
DB_PORT = 5432
DB_USER = "mala_user"
DB_PASS = os.getenv('MALA_DB_PASS')

THREAD_LIMIT = os.cpu_count()
MAX_STRING_CHAR_LIMIT = 2600
FILE_HASH_BUFFER_SIZE = 8192
SHR_CUTOFF = 40

MALA_OUTPUT_DIR = "/media/unknown/Malware Repo/malware/mala/mala"

TOOLCHAIN = [
    # Comment out what you don't want but
    # strings *will* break if you don't use '-t,d' in your args
    "exiftool,-S,-j,-P",
    #"strings,-t,d,-a,-n,6",
    #"strings,-t,d,-a,-n,6,-e,l",
    #"mala_strings",
    "diec,-je",
    "diec,-jd",
    "tlsh,-ojson,-f",
    #"file,-b",
    "ssdeep,-sbc",
]

TOOL_TABLES = {
    "strings": ["t_stringinstance", "t_strings"],
    "exiftool": "t_exiftool",
    "tlsh": "t_tlsh",
    "diec": ["t_diec", "t_diec_meta", "t_diec_ent"],
    "ssdeep": "t_ssdeep",
}

EMERGENT = (
    r"e t1|oarinsl23dc87064m9u5pESACgfThby\"Iv"
    r"LDRw-_PO.NFx\\MW%VUkGHB:@,q?=];[(<Q'jX>)YKz$/Z*J+`^!&#~}{")

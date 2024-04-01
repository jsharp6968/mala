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
    "strings,-t,d,-a,-n,6",
    "strings,-t,d,-a,-n,6,-e,l",
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

EMERGENT = "e t1|oarinsl23dc87064m9u5pESACgfThby\"IvLDRw-_PO.NFx\\MW%VUkGHB:@,q?=];[(<Q'jX>)YKz$/Z*J+`^!&#~}{"

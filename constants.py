DB_NAME = "mala"
DB_HOST = "/var/run/postgresql"
DB_USER = "mala_user"
DB_PASS = "pass"

THREAD_LIMIT = 32
MAX_STRING_CHAR_LIMIT = 2600
FILE_HASH_BUFFER_SIZE = 8192
SHR_CUTOFF = 9

MALA_OUTPUT_DIR = "/media/unknown/Malware Repo/malware/mala/mala"

TOOLCHAIN = [
    "exiftool,-S,-j,-P",
    "strings,-t,x,-a,-n,6",
    "strings,-t,x,-a,-n,6,-e,l",
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

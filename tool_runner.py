import subprocess
import os
import time
import json
import hashlib
import constants
import logging as log
from constants import FILE_HASH_BUFFER_SIZE, SHR_CUTOFF, MAX_STRING_CHAR_LIMIT
from collections import Counter
from scipy.spatial.distance import cosine



def calculate_similarity(vector1, vector2):
    """Calculate cosine similarity between two vectors."""
    return 1 - cosine(vector1, vector2)


def enhanced_human_readable(text):
    """
    A heuristic function to evaluate the human readability of each line,
    which must exceed SHR_CUTOFF in order to return True.
    This version is a bit more complex to prevent strings like 'eee' scoring
    as the highest in the DB."""
    if len(text) > constants.MAX_STRING_CHAR_LIMIT:
        return False, 0

    emergent = "e t1|oarinsl23dc87064m9u5pESACgfThby\"IvLDRw-_PO.NFx\\MW%VUkGHB:@,q?=];[(<Q'jX>)YKz$/Z*J+`^!&#~}{"
    #emergent_freq = {char: idx for idx, char in enumerate(emergent, 1)}    It's the same every time...
    emergent_freq = {'e': 1, ' ': 2, 't': 3, '1': 4, '|': 5, 'o': 6, 'a': 7, 'r': 8, 'i': 9, 'n': 10, 
    's': 11, 'l': 12, '2': 13, '3': 14, 'd': 15, 'c': 16, '8': 17, '7': 18, '0': 19, '6': 20, '4': 21, 
    'm': 22, '9': 23, 'u': 24, '5': 25, 'p': 26, 'E': 27, 'S': 28, 'A': 29, 'C': 30, 'g': 31, 'f': 32, 
    'T': 33, 'h': 34, 'b': 35, 'y': 36, '"': 37, 'I': 38, 'v': 39, 'L': 40, 'D': 41, 'R': 42, 'w': 43, 
    '-': 44, '_': 45, 'P': 46, 'O': 47, '.': 48, 'N': 49, 'F': 50, 'x': 51, '\\': 52, 'M': 53, 'W': 54, 
    '%': 55, 'V': 56, 'U': 57, 'k': 58, 'G': 59, 'H': 60, 'B': 61, ':': 62, '@': 63, ',': 64, 'q': 65, 
    '?': 66, '=': 67, ']': 68, ';': 69, '[': 70, '(': 71, '<': 72, 'Q': 73, "'": 74, 'j': 75, 'X': 76, 
    '>': 77, ')': 78, 'Y': 79, 'K': 80, 'z': 81, '$': 82, '/': 83, 'Z': 84, '*': 85, 'J': 86, '+': 87, 
    '`': 88, '^': 89, '!': 90, '&': 91, '#': 92, '~': 93, '}': 94, '{': 95}

    text_freq = Counter(text)
    text_vector = [text_freq.get(char, 0) for char in emergent]
    emergent_vector = list(range(len(emergent), 0, -1))

    similarity_score = calculate_similarity(text_vector, emergent_vector)
    diversity_score = len(set(text)) / len(text)    # length independent
    #entropy_score = calculate_entropy(text)         # length independent
    combined_score = similarity_score * 100 + diversity_score * 50 #+ entropy_score * 10

    return combined_score > constants.SHR_CUTOFF, int(combined_score)


def simple_human_readable(text):
    """
    A heuristic function to evaluate the human readability of each line,
    which must exceed SHR_CUTOFF in order to return True.
    
    This is mostly arbitrary but you usually see [e t a o i n...]
    when you order characters by frequency descending in human written text.
    Would be interesting to train this on whatever language/dataset you want to
    score highly/search for."""
    if len(text) > constants.MAX_STRING_CHAR_LIMIT:
        return False, 0

    emergent = """e t1|oarinsl23dc87064m9u5pESACgfThby"IvLDRw-_PO.NFx\MW%VUkGHB:@,q?=];[(<Q'jX>)YKz$/Z*J+`        ^!&#~}{"""

    # Used to be "etaoinshrdlucmfgypwbvkxjqz" - the above is calculated from top 10k common strings
    score = 0
    for char in text:
        if char in emergent:
            score += len(emergent) - emergent.index(char)
    if score == 0:
        return False, 0
    score_float = float((score * 1.0) / (len(text)))
    score_int = int(score_float)
    if score_int > constants.SHR_CUTOFF:
        return True, score_int
    return False, 0


def get_emergent(text):
    """Get all distinct characters by frequency descending from text."""
    chars = {}
    for char in text:
        if char in chars.keys():
            chars[char] += 1
        else:
            chars[char] = 1
            chars.add(char)
    sorted_chars = dict(sorted(chars.items(), 
                    key=lambda item: item[1], 
                    reverse=True))
    return chars


class ToolRunner():
    def __init__(self, dao, toolchain, single_tool=None):
        self.dao = dao
        self.tool_configs = {}
        if single_tool:
            self.toolchain = [single_tool,]
        self.toolchain = toolchain
        self.parse_all_tool_cmdlines()
        

    def get_file_data(self, file):
        """
        Take a file, get hashes and the size and check if we know it.
        Insert it into the DB if not.
        """
        md5, sha256, sha1, fsize = self.get_file_hashes(file)
        existing_id =  self.dao.get_via_sha256(sha256)
        if existing_id is not None:
            # File is already known to the DB
            return existing_id, True
        basename = os.path.basename(file)
        file_data = {
            "basename": basename,
            "md5": md5,
            "sha256": sha256,
            "sha1": sha1,
            "path": file,
            "fsize": fsize,
        }
        inserted_id = -1
        try:
            inserted_id = self.dao.insert_malware_file(file_data)
        except Exception as e:
            print(e)
            print("Error getting file data in ToolRunner.")
        if not inserted_id:
            print(f"We don't have a file id for file {file}")
            inserted_id = -1
        return inserted_id, False

    def get_file_hashes(self, file_path):
        """
        Get filesize, MD5, SHA1 and SHA256.
        """
        hash_md5 = hashlib.md5()
        hash_sha256 = hashlib.sha256()
        hash_sha1 = hashlib.sha1()
        fsize = 0

        with open(file_path, "rb") as file:
            for chunk in iter(lambda: file.read(constants.FILE_HASH_BUFFER_SIZE), b""):
                hash_md5.update(chunk)
                hash_sha256.update(chunk)
                hash_sha1.update(chunk)
                fsize += len(chunk)

        return hash_md5.hexdigest(), hash_sha256.hexdigest(), hash_sha1.hexdigest(), fsize


    def parse_all_tool_cmdlines(self):
        """
        Split all toolchain entries into tool + args.
        Store in self.
        """
        for tool_cmdline in self.toolchain:
            self.parse_tool_cmdline(tool_cmdline)


    def execute_tool(self, malware_path, tool, args=[]):
        """
        Execute a tool with nullable args on an absolute path.
        Returns an array of strings - lines.
        """
        process = subprocess.Popen(
            [tool] + args + [malware_path],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
        )
        stdout, stderr = process.communicate()
        return stdout.decode("utf-8")


    def parse_tool_cmdline(self, tool_cmdline):
        """
        Split a toolchain entry into tool + args and return.
        """
        tool_args = []
        if "," in tool_cmdline:
            tool_call = tool_cmdline.split(",")
            tool = tool_call[0]
            tool_args = tool_call[1:]
        else:
            tool = tool_cmdline
        if tool_cmdline not in self.tool_configs.keys():
            self.tool_configs[tool_cmdline] = (tool, tool_args)
        return tool, tool_args

    
    def parse_strings_data(self, tool_data):
        """
        Take the output of the strings linux binary and submit unique values to a
        heuristic function to evaluate the human readability of each line,
        which must exceed SHR_SCORE in order to return True.

        - This assumes you are calling:  strings -t x __other_args__
        """
        strings = []
        scores = []
        addresses = []
        count = 0
        for line in tool_data:
            count += 1
            try:
                line = line.strip()
                if not " " in line or line is None:
                    continue
                line_items = line.split(" ", 1)
                address = line_items[0]
                string = line_items[1]
                #result_tuple = simple_human_readable(string)
                result_tuple = enhanced_human_readable(string)
                result = result_tuple[0]
                score = result_tuple[1]
                if result:
                    strings.append(string)
                    addresses.append(address if len(address) % 2 == 0 else '0' + address)
                    scores.append(score)
            except Exception as e:
                print(e)            
        return strings, scores, addresses


    def parse_exiftool_data_json(self, tool_data):
        """Turn a list of single k:v dicts into one dict."""
        concatenated_output = "".join([line for line in tool_data])
        json_tool_output = json.loads(concatenated_output)

        exif_table = {}
        for entry in json_tool_output:
            exif_table = exif_table | entry
        return exif_table


    def insert_tool_data(self, tool_data, tool_name, file_id):
        """
        Match-case for different tools, the dao holds the function.
        Expects tool data to be a list of lines.
        """
        match tool_name:
            case "strings":
                strings, scores, addresses = self.parse_strings_data(tool_data)
                self.dao.insert_string_instances(strings, scores, addresses, file_id)
            case "exiftool":
                tool_data = self.parse_exiftool_data_json(tool_data)
                self.dao.insert_exif_json(tool_data, file_id)
            case "diec":
                tool_data = json.loads("".join(tool_data))
                self.dao.insert_diec_json(tool_data, file_id)
            case "tlsh":
                tool_data = json.loads("".join(tool_data))
                self.dao.insert_tlsh_json(tool_data, file_id)
            case "ssdeep":
                self.dao.insert_ssdeep_hash(tool_data, file_id)


    def execute_one_tool(self, file_id, malware_path, tool_config):
        """
        Run one tool on a file, handling exceptions with a printout.
        """
        try:
            tool_data = self.execute_tool(
                malware_path=malware_path, 
                tool=tool_config[0], 
                args=tool_config[1]
                )
            self.insert_tool_data(
                tool_data=tool_data,
                tool_name=tool_config[0],
                file_id=file_id
            )
        except Exception as e:
            print(repr(e))
            print(file_id,malware_path,tool_config,argstring)
            print(f"Skipping tool {tool_config} on sample {file_id}")
         

    def execute_all_tools(self, file_id, malware_path):
        """
        Run the whole tool list on a file, handling exceptions
        on a per-tool basis so no tools are missed.
        """
        for key in self.tool_configs.keys():
            try:
                tool_config = self.tool_configs[key]
                tool_data = self.execute_tool(
                    malware_path=malware_path, 
                    tool=tool_config[0], 
                    args=tool_config[1]
                    )
                self.insert_tool_data(
                    tool_data=tool_data,
                    tool_name=tool_config[0],
                    file_id=file_id
                )
            except Exception as e:
                print(repr(e))
                print(file_id,malware_path,tool_config,argstring)
                print(f"Skipping tool {key} on sample {file_id}")

    
    def verify_all_tools(self, file_id):
        """
        Check each table associated to each tool for the file_id,
        and if we don't find it, retry execution.
        Strings requires accessing the biggest table in the DB so
        we do that once and store it in self for efficiency (TODO)
        """
        table_mapping = constants.TOOL_TABLES
        for key in self.tool_configs.keys():
            tool_config = self.tool_configs[key]
            if tool_config[0] == "strings":
                # Strings needs to be handled in a bulk query
                continue
            target_table = table_mapping[tool_config[0]]
            if isinstance(target_table, list):
                for table in target_table:
                    rowcount = self.dao.get_file_rowcount(file_id, table)
                    if not rowcount > 0:
                        print(f"Missing tool {key} in table {table} output for file {file_id}")
                        try:
                            self.execute_one_tool(
                                file_id=file_id,
                                malware_path=self.dao.get_fpath_from_id(file_id),
                                tool_config=self.parse_tool_cmdline(
                                [c for c in constants.TOOLCHAIN if c.startswith(key)][0],
                                )
                            )
                        except Exception as e:
                            print(f"{e}\nTool might not still be in the toolchain.")
            else:
                rowcount = self.dao.get_file_rowcount(file_id, target_table)
                if not rowcount > 0:
                    print(f"Missing tool {key} in table {target_table} output for file {file_id}")
                    try:
                        self.execute_one_tool(
                            file_id=file_id,
                            malware_path=self.dao.get_fpath_from_id(file_id),
                            tool_config=self.parse_tool_cmdline(
                                [c for c in constants.TOOLCHAIN if c.startswith(key)][0],
                                )
                        )
                    except Exception as e:
                        print(f"{e}\nTool might not still be in the toolchain.")

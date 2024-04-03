# mala
Mala can run a toolchain on your whole malware zoo and store all the output in a DB. The goal is to enable deep analysis across a large corpus of malware.

Mala will ingest directory structures of malware samples, extracting them from .7z files first if needed, and then check if the file is known (by SHA256) and if not, add it. It can skip archives it has already successfully processed also. Then it will process a toolchain on each file and store the output for each tool in a separate table.


## Install
Run `setup.sh` with sudo and then make sure you have all the tools you want installed.
By default mala will attempt to use `tlsh`, `strings`, `exiftool`, `diec` and `ssdeep`, so you can either comment those out (lines 17-24 in `constants.py`), or install them.
Mala uses subprocess - anything you can run, it can run. Just add your tools to the toolchain in `constants.py` in the form of a cmdline *with spaces replaced by commas*:

`"exiftool,-S,-j,-P"`

## Run
Mala defaults to using a Unix socket, which Postgres does not make available unless the relevant line of the `postgresql.conf` is uncommented. If you want to use the network stack over localhost (or a remote/LAN DB) then change the DB_HOST value in `constants.py`.

If you want to extract archives and then process the contents, specify both the `-d` arg for where the .7z files are, and the `-dd` arg for where those archives should all be extracted to like so:

`python main.py -d /home/unknown/code/mala/samples/input/ -dd /home/unknown/code/mala/samples/extracted/VirusShare/ -p`


Example with directory full of extracted malware samples:

`python main.py -d /home/unknown/code/mala/samples/extracted/vxug/InTheWild.0013/ --extracted`


You can use it with a single file by passing -s:

`python main.py -s malware.exe --extracted`


You can also use it with a single tool by passing -st and then any cmdline *with spaces replaced by commas*:

`python main.py -d /home/unknown/code/mala/samples/extracted/vxug/InTheWild.0013/ --extracted -st "exiftool,-S,-j,-P"`


You can also combine these, running a single tool on a single file:

`python main.py -s malware.exe --extracted -st "exiftool,-S,-j,-P"`


To verify if the current toolchain has been successfully run on each input sample, include the `-v` arg.


Mala also takes an argument `-p` or `--package` which indicates this is a publicly distributed archive. For efficiency, it will store meta-information about this archive in the DB and check if any new package is known already before processing it. This only applies when mala does the extraction itself - if you do this yourself and use --extracted, `-p` will not work. Beware of collisions between archives with dates as names instead of a source name + identifier such as `Virusshare.486.7z` or `InTheWild.0042.7z`.

## Tools
When adding tools to the toolchain in mala, the workflow is:

-   Install the tool and get it working from the cli
-   Define the table structure in a function to create and call in in `create_db.py:setup()`
-   Add the cmdline in `constants.py:TOOLCHAIN`
-   Add a case for it in `tool_runner.py:ToolRunner:insert_tool_data()` with any preprocessing needed to the data then calling the dao insert function
-   Add a dao insert function in `mala_dao.py:MalaDao()` to insert it into the DB
- To verify it, add the table (or list of tables, see below) into `constants.py:TOOL_TABLES`

Some generic functions exist in MalaDAO for generating tables.

### Default Tools
By default, mala ships with some basic tools as follows:

`exiftool,-S,-j,-P` - Exiftool, very short fomat, json output format, preserve file modtime

~~`strings,-t,d,-a,-n,6` - Strings, output with address in decimal format, all sections, 6 chars minimum~~

~~`strings,-t,d,-a,-n,6,-e,l` - Strings, output with address in decimal format, all sections, 6 chars minimum, 16-bit littleendian encoding~~

`mala_strings` - A Rust binary whose source is in `mala_strings.rs` and can be compiled and placed in `/usr/bin/` to be used systemwide. This replaced GNU strings above and is 20% faster.

`diec,-je` - DetectItEasy compiled in C, output in json format, entropy scan

`diec,-jd` - DetectItEasy compiled in C, output in json format, deep section scan

`tlsh,-ojson,-f` - Get the TLSH hash of the file

`ssdeep,-sbc` - ssdeep, silent mode, bare output, comma-separated output

### Strings
Strings is probably the most interesting tool in the basic toolkit. There is all kinds of interesting data to be found in your `t_strings` table, like passwords, keys, crypto wallet addresses, URLs, domains, email addresses, tool cmdlines etc.

The `t_strings` table has a uniqueness constraint on the `value` column, and a reference by id to each instance of that string is held in `t_stringinstance` along with the `file_id`, `address` in decimal where the string is located in the binary and the `score`.

Unfortunately it is also the bane of the whole application due to the volume of data. The output of `strings` has to be filtered in some way as there is so much noise, and the table holding references `t_stringinstance` balloons to enormous sizes.

The score comes from a heuristic function to analyse character frequency, using a minimum threshold for keeping the string:

```
for char in text:
    # This is prone to score very highly for "eeeeeeeeeeeee" 
    score += len(EMERGENT) - EMERGENT.find(char)
```
Where `EMERGENT` is a string composed of characters ranked descending in order of frequency. This is a good way to blindly find human readable text inside noise if your `EMERGENT` string is something like `"etaoinshrdlucmfgypwbvkxjqz"`, but as noted by the comment it scores repetitve strings too highly. 

The latest attempt uses cosine from scipy on the text vectors to detect how similar the frequency of characters in the received string is to that of `EMERGENT`.

I have seen that some interesting strings such as URLs and such score quite low, so ideally every string would be evaluated against a list of regexes before being dumped due to a low score. But runtime is already majorly impacted by current processing.

## Note
I am not a malware analyst. In a way, I made this tool to make it easier for me to learn malware analysis by finding samples which are interesting to me for some reason, usually based on finding a weird string via SQL. Python and SQL I am confident with, but I am a beginner when it comes to handling malware, and that side of things is an area where I would love feedback from people who know that they are talking about.
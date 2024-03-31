# mala
A tool to ingest static malware analysis tool output at scale and store it in a DB. The goal is to enable deep analysis across a large corpus of malware.
Mala will ingest directory structures of malware samples, extracting them from .7z files first if needed, and then check if the file is known (by SHA256) and if not, add it. Then process a toolchain and store the output for each tool in a separate table.

# Install
Run `setup.sh` with sudo and then make sure you have all the tools you want installed.
By default mala will attempt to use `tlsh`, `strings`, `exiftool`, `diec` and `ssdeep`, so you can either comment those out (lines 17-24 in `constants.py`), or install them.
Mala uses subprocess - anything you can run, it can run.

# Run
Mala defaults to using a Unix socket, which Postgres does not make available unless the relevant line of the `postgresql.conf` is uncommented. If you want to use the network stack (or a remote/LAN DB) then change the DB_HOST value in `constants.py`.

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

Mala also takes an argument `-p` or `--package` which indicates this is a publicly distributed archive. For efficiency, it will store meta-information about this archive in the DB and check if any new package is known already before processing it. This only applies when mala does the extraction itself - if you do this yourself and use --extracted, `-p` will not work.


# Packages
Mala can check if it already knows an archive of malware by basename (ie Virusshare.486.7z -> `Virusshare.486`) in the `t_package` table. It will then count the files inside the archive, then search the file table and count files which contain that basename in their absolute path structure in the `path` column of `t_file`. If the count of files is more than 90% the count of the files inside the archive, we count it as known. A naive equals check would not work as some archives do contain samples which cannot be hashed for whatever reason, and we might have already encountered a file in an earlier ingested package, so the known percentage is sometimes less than 100% even when mala encountered no errors.
In any case, it's just an optimisation because no file gets processed if it is known, this check just avoids unpacking and processing archives that we know already.



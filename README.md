# mala
A tool to ingest static malware analysis tool output at scale and store it in a DB. The goal is to enable deep analysis across a large corpus of malware.
Mala will ingest directory structures of malware samples, extracting them from .7z files first if needed, and then check if the file is known (by SHA256) and if not, add it. Then process a toolchain and store the output for each tool in a separate table.

# Install
Run `setup.sh` with sudo and then make sure you have all the tools you want installed.
By default mala will attempt to use `tlsh`, `strings`, `exiftool`, `diec` and `ssdeep`, so you can either comment those out (lines 17-24 in `constants.py`), or install them.
Mala uses subprocess - anything you can run, it can run.

# Run
Mala defaults to using a Unix socket, which Postgres does not make available unless the relevant line of the `postgresql.conf` is uncommented. If you want to use the network stack (or a remote/LAN DB) then change the DB_HOST value in `constants.py`.
Example with extracted archive:
`python main.py -d /home/unknown/code/mala/samples/extracted/vxug/InTheWild.0013/ --extracted`

You can use it with a single file by passing -s:
`python main.py -s malware.exe --extracted`

You can also use it with a single tool by passing -st and then any cmdline *with spaces replaced by commas*:
`python main.py -d /home/unknown/code/mala/samples/extracted/vxug/InTheWild.0013/ --extracted -st "exiftool,-S,-j,-P"`

You can also combine these, running a single tool on a single file:
`python main.py -s malware.exe --extracted -st "exiftool,-S,-j,-P"`

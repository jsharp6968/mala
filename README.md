# mala
A tool to ingest static malware analysis tool output at scale.

# Install
Run setup.sh with sudo and then make sure you have all the tools you want installed.
By default mala will attempt to use tlsh, strings, exiftool, diec and ssdeep, so you can either comment those out, or install them.
Mala uses subprocess - anything you can run, it can run.

# Run
Example with extracted archive:
`python main.py -d /home/unknown/code/mala/samples/extracted/vxug/InTheWild.0013/ --extracted`


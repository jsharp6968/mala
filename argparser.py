import argparse

class MalaArgParser():
    def __init__(self):
        parser = argparse.ArgumentParser(description="argparser for mala")
        parser.add_argument("--filename", type=str, help="File for single file mode.")
        parser.add_argument(
            "-d", "--dir", type=str, help="A directory to scan for 7z files.", default="."
        )
        parser.add_argument(
            "-dd", "--dest_dir", type=str, help="A directory to extract malware samples into.", default="."
        )
        parser.add_argument(
            "-e", "--extracted", action="store_true", help="All samples already extracted."
        )
        parser.add_argument(
            "-s", "--singleshot", action="store_true", help="Ingest one malware sample."
        )
        parser.add_argument(
            "-v", "--verify", action="store_true", help="If we know a sample, verify the current toolchain has been run and get any missing tool outputs."
        )
        parser.add_argument(
            "-st", "--single_tool", type=str, help="One tool cmdline to run on every input sample, in quotes.", default=""
        )
        parser.add_argument(
            "-fl", "--filelimit", type=int, default=0, help="How many samples to process into MalaDB."
        )
        self.args = parser.parse_args()
    

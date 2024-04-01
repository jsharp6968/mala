import sys
import time
#import memray 
import logging as log
from file_handler import MalaFileHandler
from create_db import setup
from core import *
from argparser import MalaArgParser


setup()
cmdline = " ".join(sys.argv[1:])
log.basicConfig(filename='mala.log', level=log.DEBUG,
                format='%(asctime)s - %(levelname)s - %(message)s')
parser = MalaArgParser()
args = parser.args
log.debug(f'Starting mala with command "{cmdline}"')
start_time = time.time()

mfh = MalaFileHandler(args)
target_files = []
if args.dir is not None and args.dir != "." and not args.extracted:
    target_files = unzip_files(mfh, args)
    args.extracted = True
    args.dir = args.dest_dir

#timestamp = str(int(time.time()))
#print(f"Tracking with memray output to: output_{timestamp}.bin")
#with Tracker(f"output_{timestamp}.bin"):
target_files = run(args, mfh, target_files)
runtime = time.time() - start_time
samples_per_second = len(target_files) / runtime
print(f"Handled {len(target_files)} malware samples in {runtime:.3f} seconds.")
print(f"Processing speed: {samples_per_second:.3f} samples per second.")

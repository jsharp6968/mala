import py7zr
import argparse
import os
import sys
import time
import logging as log
import concurrent.futures as c_futures
from file_handler import MalaFileHandler
from create_db import setup
from mala_dao import MalaDAO
from tool_runner import ToolRunner
import constants


def extract_sample(path, dest):
    """
    Py7zr extraction and chmod to prevent detonation.
    Assumes the password is 'infected'.
    """
    with py7zr.SevenZipFile(path, mode="r", password="infected") as z:
        z.extractall(path=dest)
        os.chmod(dest, 0o644)


def handle_extraction(file, dest_dir):
    """
    Check for, create if not exists the unzipped file without .7z extension.
    """
    basename = os.path.basename(file)
    target_path = os.path.join(dest_dir, basename.replace(".7z", ""))
    try:
        if not os.path.exists(target_path):
            extract_sample(file, dest_dir)
    except:
        log.debug("Failed to extract ", file, target_path)


def write_output(target_path, tool_output):
    """
    Write all tool outputs for a sample to a textfile.
    """
    basename = os.path.basename(target_path)
    output_filename = MALA_OUTPUT_DIR + basename + ".mala"
    if not os.path.exists(output_filename):
        with open(output_filename, "w") as outfile:
            outfile.write("\n".join(tool_output))


def worker_function(file_chunk, toolchain, single=None):
    """
    The main worker function of the program. Is a process run by concurrent futures.
    Creates its own DAO and ToolRunner, parses the tools list and processes a chunk
    of the total file list, the prints stats and exits.
    """
    dao = MalaDAO()
    tool_runner = ToolRunner(dao=dao, toolchain=toolchain)
    count = 0
    handled = 0
    verified = 0
    try:
        for file in file_chunk:
            count += 1
            file_id, already_known = tool_runner.get_file_data(file)
            if already_known and single is None:
                tool_runner.verify_all_tools(file_id)
                log.debug(f"Verified file {file_id}")
                verified += 1
                continue
            tool_runner.execute_all_tools(file_id, file)
            handled += 1
    except Exception as e:
        log.debug(f"{e}\nAn error occurred running a worker. Destroying worker now.")
    finally:
        dao.destroy()
        log.debug(f"Thread finished. Processed: {count} Verified: {verified} NEW:{handled} ")

def singleshot(filename, toolchain):
    """
    Run all tools on just one sample.
    """
    worker_function(filename, toolchain)
    runtime = time.time() - start_time
    samples_per_second = 1 / runtime
    print(f"Time:{runtime:.6f} seconds.")
    log.debug(f"Handled this malware sample in {runtime:.6f} seconds.")
    exit()

def run(args, mfh, target_files):
    """
    TODO: Split into more application state
    """
    if args.single_tool:
        print("RUNNING IN SINGLE TOOL MODE")
        log.debug("RUNNING IN SINGLE TOOL MODE")
        constants.TOOLCHAIN = [args.single_tool,]
    if args.singleshot:
        log.debug(f'Running mala on a single file: "{args.filename}"')
        singleshot([args.filename,], constants.TOOLCHAIN) 
        runtime = time.time() - start_time
        samples_per_second = 1 / runtime
        print(f"Time:{runtime:.6f} seconds.")
        log.debug(f"Handled this malware sample in {runtime:.6f} seconds.")
        exit()
    if args.extracted:
        log.debug(f"Checking target path {args.dir}")
        target_files = mfh.get_all_file_paths()

    if len(target_files) > args.filelimit and args.filelimit > 0:
        target_files = target_files[:args.filelimit]

    log.debug(f"Handling {len(target_files)} malware samples.")
    chunk_size = len(target_files) // constants.THREAD_LIMIT
    file_chunks = [
        target_files[i : i + chunk_size] for i in range(0, len(target_files), chunk_size)
    ]
    log.debug(f"Running with {constants.THREAD_LIMIT} threads and {len(file_chunks)} chunks")
    with c_futures.ProcessPoolExecutor(max_workers=constants.THREAD_LIMIT) as executor:
        if args.single_tool:
            futures = [
                executor.submit(worker_function, file_chunk, constants.TOOLCHAIN, single=True)
                for file_chunk in file_chunks
            ]
            c_futures.wait(futures)
        else:
            futures = [
                executor.submit(worker_function, file_chunk, constants.TOOLCHAIN)
                for file_chunk in file_chunks
            ]
            c_futures.wait(futures)
    return target_files


    def unzip_files(mfh, args):
        target_files = mfh.find_7z_files()
        if target_files:
            with c_futures.ProcessPoolExecutor(max_workers=constants.THREAD_LIMIT) as executor:
                futures = [
                    executor.submit(handle_extraction, file, args.dest_dir)
                    for file in target_files
                ]
                c_futures.wait(futures)

        log.debug(f"Extracted all {len(target_files)} files.")
        return target_files
        


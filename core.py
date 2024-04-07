import py7zr
import os
import sys
import logging as log
import concurrent.futures as c_futures
from mala_dao import MalaDAO
from tool_runner import ToolRunner
import constants


def extract_sample(path, dest):
    """
    Py7zr extraction and chmod to prevent detonation.
    Assumes the password is 'infected'.
    """
    with py7zr.SevenZipFile(path, mode="r", password="infected") as zip_file:
        zip_file.extractall(path=dest)
        os.chmod(dest, 0o644)


def extract_package(path, dest):
    """
    Py7zr extraction of an archive.
    Assumes the password is 'infected'.
    """
    with py7zr.SevenZipFile(path, mode="r", password="infected") as zip_file:
        zip_file.extractall(path=dest)


def handle_extraction(file, dest_dir, package=False):
    """
    Check for, create if not exists the unzipped file without .7z extension.
    If the extraction result is a directory, pass it back.
    """
    basename = os.path.basename(file)
    target_path = os.path.join(dest_dir, basename.replace(".7z", ""))
    try:
        if not os.path.exists(target_path):
            if package:
                extract_package(file, dest_dir)
            else:
                extract_sample(file, dest_dir)
    except Exception as error:
        log.error(f"Failed to extract {file} {target_path}")
        log.error(error)


def write_output(target_path, tool_output):
    """
    Write all tool outputs for a sample to a textfile.
    """
    basename = os.path.basename(target_path)
    output_filename = constants.MALA_OUTPUT_DIR + basename + ".mala"
    if not os.path.exists(output_filename):
        with open(output_filename, "w", encoding="utf-8") as outfile:
            outfile.write("\n".join(tool_output))


def worker_function(file_chunk, toolchain, verify=None):
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
            if already_known:
                if verify:
                    tool_runner.verify_all_tools(file_id)
                    log.debug(f"Verified file {file_id}")
                    verified += 1
                continue
            tool_runner.execute_all_tools(file_id, file)
            handled += 1
    except Exception as e:
        log.error(f"{e}\nAn error occurred running a worker. Destroying worker now.")
    finally:
        dao.destroy()
        log.debug(f"Thread finished. Processed: {count} Verified: {verified} NEW:{handled} ")


def singleshot(filename, toolchain):
    """
    Run all tools on just one sample.
    """
    worker_function(filename, toolchain)
    sys.exit()


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
    if args.extracted and not target_files:
        log.debug(f"Checking target path {args.dir}")
        target_files = mfh.get_all_file_paths()

    if len(target_files) > args.filelimit and args.filelimit > 0:
        target_files = target_files[:args.filelimit]

    if len(target_files) == 0:
        print("No files to process, exiting.")
        return target_files
    log.debug(f"Handling {len(target_files)} malware samples.")
    chunk_size = len(target_files) // constants.THREAD_LIMIT
    file_chunks = [
        target_files[i : i + chunk_size] for i in range(0, len(target_files), chunk_size)
    ]
    log.debug(f"Running with {constants.THREAD_LIMIT} threads and {len(file_chunks)} chunks")
    with c_futures.ProcessPoolExecutor(max_workers=constants.THREAD_LIMIT) as executor:
        futures = [
            executor.submit(worker_function, file_chunk, constants.TOOLCHAIN, verify=args.verify)
            for file_chunk in file_chunks
        ]
        c_futures.wait(futures)
    return target_files


def unzip_files(mfh, args):
    target_files = mfh.find_7z_files()
    if target_files:
        with c_futures.ProcessPoolExecutor(max_workers=constants.THREAD_LIMIT) as executor:
            futures = [
                executor.submit(handle_extraction, file, args.dest_dir, args.package)
                for file in target_files
            ]
            c_futures.wait(futures)

    log.debug(f"Extracted all {len(target_files)} files.")
    if args.package:
        new_target_files = []
        for target_file in target_files:
            # In the dest dir, find the filename without .7z extension,
            # walk its contents and return into target_files
            extracted_dir = os.path.basename(target_file.replace('.7z', ''))
            abs_dirpath = os.path.join(args.dest_dir, extracted_dir)
            if os.path.exists(abs_dirpath) and os.path.isdir(abs_dirpath):
                new_target_files += mfh.get_all_file_paths(abs_dirpath)
        target_files = new_target_files
    return target_files

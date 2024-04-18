import os
import sys
import logging as log
import concurrent.futures as c_futures
import py7zr
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
    file_ids = []
    try:
        for file in file_chunk:
            count += 1
            file_id, already_known = tool_runner.get_file_data(file)
            file_ids.append(file_id)
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
    return (count, handled, verified, file_ids)


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
        return [1]
    log.debug(f"Handling {len(target_files)} malware samples.")
    file_chunks = balance_target_file_chunks(target_files)
    log.debug(f"Running with {constants.THREAD_LIMIT} threads and {len(file_chunks)} chunks")
    with c_futures.ProcessPoolExecutor(max_workers=constants.THREAD_LIMIT) as executor:
        futures = [
            executor.submit(worker_function, file_chunk, constants.TOOLCHAIN, verify=args.verify)
            for file_chunk in file_chunks
        ]
        c_futures.wait(futures)
        collate_stats([future.result() for future in futures], mfh)
    return target_files


def collate_stats(results, mfh):
    """
    Gather all stats and hand off to mfh to store in executions table.
    Then add a record in t_file_ingest linking each file to this execution.
    """
    stats = {
        "fcount_sanity": 0,
        "handled_count": 0,
        "verified_count": 0,
    }
    file_ids = []
    for result in results:
        stats["fcount_sanity"] += result[0]
        stats["handled_count"] += result[1]
        stats["verified_count"] += result[2]
        file_ids += result[3]
    mfh.store_stats(stats)
    mfh.store_execution()
    mfh.associate_files(file_ids)


def balance_target_file_chunks(target_files):
    """
    Equalize the total raw data size in each chunk to try and ensure consistent thread finishing
    times. First get all sizes and sort the dictionary, then iterate descending by size and give
    the smallest chunk the next file.
    """
    total_volume = 0
    file_sizes = {}
    for file in target_files:
        fsize = os.path.getsize(file)
        total_volume += fsize
        file_sizes[file] = fsize
    sorted_files = sorted(file_sizes.items(), key=lambda item: item[1], reverse=True)
    num_bins = constants.THREAD_LIMIT
    bins = [[] for _ in range(num_bins)]
    bin_sizes = [0] * num_bins
    # Greedy allocation of largest file to bin of minimum size
    for file, size in sorted_files:
        min_bin_index = bin_sizes.index(min(bin_sizes))
        bins[min_bin_index].append(file)
        bin_sizes[min_bin_index] += size
    return bins


def unzip_files(mfh, args):
    """
    Use 2 workers to extract all Zip files.
    Turns out load balancing this stuff is NP-Hard.
    """
    target_files = mfh.find_7z_files()
    if not target_files:
        return []

    with c_futures.ProcessPoolExecutor(max_workers=2) as executor:
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

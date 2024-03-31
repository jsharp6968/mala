import os, datetime, hashlib, json, py7zr
import logging as log
from mala_dao import MalaDAO
import constants

class MalaFileHandler():
    def __init__(self, args):
        self.root_dir = args.dir
        self.args = args
        self.dao = MalaDAO()


    def check_archive_known(self, archive_path):
        archive_name = os.path.basename(archive_path)
        result = self.dao.search_package(archive_name)
        if result:
            archive_data = result[0]
            archive_dict = {
                "id": archive_data[0],
                "basename": archive_data[2],
                "md5": archive_data[1],
                "path": archive_data[3],
                "fsize": archive_data[4],
                "fcount": archive_data[6],
                "date_ingested": archive_data[5].strftime("%Y-%m-%dT%H:%M:%S")
            }
            stripped_basename = archive_dict['basename'].replace('.7z', '')
            known_files = self.dao.get_package_file_rowcount(stripped_basename)
            known_ratio = known_files * 1.0 / int(archive_dict['fcount']) * 1.0
            if known_ratio >= 0.9:
                # Sometimes archives contain files which cannot for whatever reason be hashed
                # They might be too small or broken/corrupted in some way
                # Or they could be known from a previous package
                # This is why a threshold is needed
                log.debug(f"Archive {archive_name} is {known_ratio*100}% known to the DB.")
                print(json.dumps(archive_dict, indent=4))
                return True
        else:
            print(f"New archive {archive_name}.")
        return False


    def add_archive(self, archive_path):
        basename = os.path.basename(archive_path)
        ingestion_date = datetime.datetime.now().strftime("%Y-%m-%dT%H:%M:%S")
        md5,fsize = self.get_archive_info(archive_path)
        with py7zr.SevenZipFile(archive_path, mode='r') as archive:
            fcount = len(archive.getnames())
        archive_data = {
            "basename": basename,
            "md5": md5,
            "path": archive_path,
            "fsize": fsize,
            "date_ingested": ingestion_date,
            "fcount": fcount
        }
        package_id = self.dao.insert_package(archive_data)
        return package_id


    def get_archive_info(self, file_path):
        """
        Get filesize, MD5, SHA1 and SHA256.
        """

        hash_md5 = hashlib.md5()
        fsize = 0

        with open(file_path, "rb") as file:
            for chunk in iter(lambda: file.read(constants.FILE_HASH_BUFFER_SIZE * 2), b""):
                hash_md5.update(chunk)
                fsize += len(chunk)

        return hash_md5.hexdigest(), fsize


    def find_7z_files(self, path=None):
        """
        Recursively searches for .7z files and returns their absolute paths.
        """
        if not path:
            path = self.root_dir
        seven_z_files = []
        for dirpath, dirnames, filenames in os.walk(self.root_dir):
            for file in filenames:
                if file.endswith(".7z"):
                    full_path = os.path.join(dirpath, file)
                    if self.args.package:
                        if not self.check_archive_known(full_path):
                            self.add_archive(full_path)
                            seven_z_files.append(full_path)
                    else:
                        seven_z_files.append(full_path)
        seven_z_files = list(set(seven_z_files))
        return seven_z_files


    def get_all_file_paths(self, path=None):
        """
        Recursively searches for non .7z and returns their absolute paths.
        """
        if not path:
            path = self.root_dir
        extracted_files = []
        for dirpath, dirnames, filenames in os.walk(path):
            for file in filenames:
                if not file.endswith(".7z"):
                    full_path = os.path.join(dirpath, file)
                    extracted_files.append(full_path)
        extracted_files = list(set(extracted_files))
        return extracted_files

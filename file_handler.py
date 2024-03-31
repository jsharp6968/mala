import os
from mala_dao import MalaDAO

class MalaFileHandler():
    def __init__(self, root_dir):
        self.root_dir = root_dir
        self.dao = MalaDAO()


    def check_archive_known(self, archive_name):
        pass



    def find_7z_files(self):
        """
        Recursively searches for .7z files and returns their absolute paths.
        """
        seven_z_files = []
        for dirpath, dirnames, filenames in os.walk(self.root_dir):
            for file in filenames:
                if os.path.isfile(file) and file.endswith(".7z"):
                    full_path = os.path.join(dirpath, file)
                    seven_z_files.append(full_path)
        seven_z_files = list(set(seven_z_files))
        return seven_z_files


    def get_all_file_paths(self):
        """
        Recursively searches for non .7z and returns their absolute paths.
        """
        extracted_files = []
        for dirpath, dirnames, filenames in os.walk(self.root_dir):
            for file in filenames:
                if not file.endswith(".7z"):
                    full_path = os.path.join(dirpath, file)
                    extracted_files.append(full_path)
        extracted_files = list(set(extracted_files))
        return extracted_files

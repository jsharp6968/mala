import os

class MalaFileHandler():
    def __init__(self, root_dir):
        self.root_dir = root_dir

    def find_7z_files(self):
        """Recursively searches for .7z files and returns their absolute paths."""
        seven_z_files = []
        for dirpath, dirnames, filenames in os.walk(self.root_dir):
            for file in filenames:
                if file.endswith(".7z") and "РОСАВІАЦІЯ.7z" not in file:
                    full_path = os.path.join(dirpath, file)
                    seven_z_files.append(full_path)
        seven_z_files = list(set(seven_z_files))
        return seven_z_files


    def find_extracted_files(self):
        """Recursively searches for non .7z and returns their absolute paths."""
        extracted_files = []
        for dirpath, dirnames, filenames in os.walk(self.root_dir):
            for file in filenames:
                if os.path.isfile(file) and not file.endswith("7z"):
                    full_path = os.path.join(dirpath, file)
                    extracted_files.append(full_path)
        extracted_files = list(set(extracted_files))
        return extracted_files


    def get_all_file_paths(self):
        """Walk and find all files in a directory.
        Handles only already extracted files, and ignores .7z extensions."""
        file_paths = []
        for root, dirs, files in os.walk(self.root_dir):
            for file in files:
                if not file.endswith(".7z"):
                    file_path = os.path.join(root, file)
                    file_paths.append(file_path)
        file_paths = list(set(file_paths))
        return file_paths
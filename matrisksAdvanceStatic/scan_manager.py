
import os
import json
import hashlib
import fcntl
import time
from datetime import datetime

ROOT_RESULTS_FOLDER = "scanned_results"
COUNTER_FILE = ".scan_counter"
STAGING_DIR_PREFIX = ".staging"
MANIFEST_FILE = "manifest.json"
FAILED_FLAG = "FAILED.flag"

class ScanManager:
    def __init__(self, root_folder=ROOT_RESULTS_FOLDER):
        self.root_folder = os.path.abspath(root_folder)
        self.counter_path = os.path.join(self.root_folder, COUNTER_FILE)
        self.staging_dir = None
        self.final_dir = None
        self.serial_id = None

    def _lock_and_increment_counter(self):
        os.makedirs(self.root_folder, exist_ok=True)
        lock_file = os.path.join(self.root_folder, ".lock")
        while True:
            try:
                with open(lock_file, "x") as f:
                    with open(self.counter_path, "a+") as counter_f:
                        counter_f.seek(0)
                        content = counter_f.read()
                        last_id = int(content) if content.isdigit() else 0
                        new_id = last_id + 1
                        counter_f.seek(0)
                        counter_f.truncate()
                        counter_f.write(str(new_id))
                    os.remove(lock_file)
                    return new_id
            except FileExistsError:
                time.sleep(0.1)
            except Exception as e:
                if os.path.exists(lock_file):
                    os.remove(lock_file)
                raise e

    def create_scan_environment(self):
        scan_number = self._lock_and_increment_counter()
        timestamp = datetime.utcnow().strftime("%Y-%m-%dT%H-%M-%SZ")
        self.serial_id = f"SCAN-{scan_number:04d}_{timestamp}"
        
        staging_dir_name = f".staging_{self.serial_id}_{os.getpid()}"
        self.staging_dir = os.path.join(self.root_folder, staging_dir_name)
        os.makedirs(self.staging_dir, exist_ok=True)

        self.final_dir = os.path.join(self.root_folder, self.serial_id)
        
        return self.staging_dir

    def _calculate_sha256(self, file_path):
        sha256 = hashlib.sha256()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                sha256.update(chunk)
        return sha256.hexdigest()

    def generate_manifest(self):
        if not self.staging_dir:
            return

        manifest = {
            "serial_id": self.serial_id,
            "created_at": datetime.utcnow().isoformat() + "Z",
            "files": [],
            "notes": []
        }

        for filename in os.listdir(self.staging_dir):
            file_path = os.path.join(self.staging_dir, filename)
            if os.path.isfile(file_path):
                manifest["files"].append({
                    "name": filename,
                    "size_bytes": os.path.getsize(file_path),
                    "sha256": self._calculate_sha256(file_path)
                })
        
        manifest_path = os.path.join(self.staging_dir, MANIFEST_FILE)
        with open(manifest_path, "w") as f:
            json.dump(manifest, f, indent=4)

    def finalize_scan(self):
        if not self.staging_dir or not self.final_dir:
            return None

        self.generate_manifest()

        try:
            os.rename(self.staging_dir, self.final_dir)
        except OSError:
            # Fallback to copy if atomic rename fails
            try:
                import shutil
                shutil.copytree(self.staging_dir, self.final_dir)
                shutil.rmtree(self.staging_dir)
            except Exception as e:
                self.mark_as_failed(f"Failed to move staging to final directory: {e}")
                return None
        
        if self.validate_scan():
            return self.final_dir
        else:
            return None

    def validate_scan(self):
        manifest_path = os.path.join(self.final_dir, MANIFEST_FILE)
        if not os.path.exists(manifest_path):
            self.mark_as_failed("Manifest file is missing.")
            return False

        with open(manifest_path, "r") as f:
            manifest = json.load(f)

        for file_info in manifest["files"]:
            file_path = os.path.join(self.final_dir, file_info["name"])
            if not os.path.exists(file_path):
                self.mark_as_failed(f"File {file_info['name']} is missing.")
                return False
            if os.path.getsize(file_path) != file_info["size_bytes"]:
                self.mark_as_failed(f"File {file_info['name']} has incorrect size.")
                return False
            if self._calculate_sha256(file_path) != file_info["sha256"]:
                self.mark_as_failed(f"File {file_info['name']} has incorrect checksum.")
                return False
        
        return True

    def mark_as_failed(self, reason):
        if self.final_dir:
            failed_flag_path = os.path.join(self.final_dir, FAILED_FLAG)
            with open(failed_flag_path, "w") as f:
                f.write(reason)

from vector_base import VectorBase
from constants import *
import re

class Vector(VectorBase):
    description = "Checks for insecure data storage vulnerabilities, such as world-readable/writable files, external storage usage, and logging of sensitive data."
    tags = ["INSECURE_DATA_STORAGE"]

    def analyze(self) -> None:
        self.check_insecure_file_permissions()
        self.check_external_storage()
        self.check_logging_sensitive_data()

    def check_insecure_file_permissions(self):
        found_vulnerable_methods = []

        # Regex to find openFileOutput or getSharedPreferences with MODE_WORLD_READABLE or MODE_WORLD_WRITEABLE
        regex = r"(openFileOutput|getSharedPreferences)\s*\(\s*.*,\s*(1|2|MODE_WORLD_READABLE|MODE_WORLD_WRITEABLE)\s*\)"

        for method in self.analysis.get_methods():
            if method.is_external():
                continue

            try:
                source_code = method.get_source()
                if source_code:
                    matches = re.findall(regex, source_code, re.IGNORECASE)
                    if matches:
                        found_vulnerable_methods.append(method)
            except Exception as e:
                # Sometimes decompilation fails.
                pass


        if found_vulnerable_methods:
            self.writer.startWriter("INSECURE_FILE_PERMISSIONS", LEVEL_CRITICAL, "Insecure File Permissions",
                                    "The application creates files or shared preferences with world-readable or world-writable permissions.",
                                    ["Storage"], vector_name=self.vector_name)
            for method in found_vulnerable_methods:
                self.writer.write(f"Vulnerable method: {method.get_class_name()}->{method.get_name()}{method.get_descriptor()}")

    def check_external_storage(self):
        found_vulnerable_methods = []

        regex = r"Environment\.getExternalStorageDirectory\s*\(\s*\)"

        for method in self.analysis.get_methods():
            if method.is_external():
                continue

            try:
                source_code = method.get_source()
                if source_code:
                    matches = re.findall(regex, source_code)
                    if matches:
                        found_vulnerable_methods.append(method)
            except Exception as e:
                pass

        if found_vulnerable_methods:
            self.writer.startWriter("EXTERNAL_STORAGE_USAGE", LEVEL_WARNING, "External Storage Usage",
                                    "The application uses external storage, which is accessible to other applications. Sensitive data should not be stored on external storage.",
                                    ["Storage"], vector_name=self.vector_name)
            for method in found_vulnerable_methods:
                self.writer.write(f"Method using external storage: {method.get_class_name()}->{method.get_name()}{method.get_descriptor()}")

    def check_logging_sensitive_data(self):
        found_vulnerable_methods = []

        regex = r"Log\.(d|i|w|e|v)\s*\(\s*.*(password|token|key|secret).*\s*\)"

        for method in self.analysis.get_methods():
            if method.is_external():
                continue

            try:
                source_code = method.get_source()
                if source_code:
                    matches = re.findall(regex, source_code, re.IGNORECASE)
                    if matches:
                        found_vulnerable_methods.append(method)
            except Exception as e:
                pass

        if found_vulnerable_methods:
            self.writer.startWriter("LOGGING_SENSITIVE_DATA", LEVEL_WARNING, "Logging of Sensitive Data",
                                    "The application logs sensitive data, which can be accessed by other applications or through logcat.",
                                    ["Storage"], vector_name=self.vector_name)
            for method in found_vulnerable_methods:
                self.writer.write(f"Method logging sensitive data: {method.get_class_name()}->{method.get_name()}{method.get_descriptor()}")
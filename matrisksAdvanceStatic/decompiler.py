
import subprocess
import os
import xml.etree.ElementTree as ET

class Decompiler:
    def __init__(self, apk_path, output_dir):
        self.apk_path = apk_path
        self.output_dir = output_dir
        self.source_code_index = {}

    def decompile(self, jadx_path="jadx"):
        """
        Decompiles an APK file using jadx.
        """
        if not os.path.exists(self.output_dir):
            os.makedirs(self.output_dir)

        jadx_command = [
            jadx_path,
            "-d",
            self.output_dir,
            self.apk_path
        ]

        try:
            subprocess.run(jadx_command, check=True, capture_output=True, text=True)
            print(f"Decompilation successful. Output in {self.output_dir}")
            self._create_source_code_index()
            return True
        except FileNotFoundError:
            print(f"Error: '{jadx_path}' not found. Please ensure jadx is installed and in your PATH, or specify the path using the --jadx-path argument.")
            return False
        except subprocess.CalledProcessError as e:
            print(f"Decompilation failed: {e.stderr}")
            return False

    def _create_source_code_index(self):
        """
        Creates an index of the decompiled Java files.
        """
        source_dir = os.path.join(self.output_dir, "sources")
        if not os.path.exists(source_dir):
            return

        for root, _, files in os.walk(source_dir):
            for file in files:
                if file.endswith(".java"):
                    file_path = os.path.join(root, file)
                    # The class name is the file name without the .java extension
                    class_name = os.path.splitext(file)[0]
                    # To get the full class name, we need to get the package name from the path
                    # The package name is the relative path from the source_dir
                    package_path = os.path.relpath(root, source_dir)
                    if package_path != ".":
                        full_class_name = package_path.replace(os.sep, ".") + "." + class_name
                    else:
                        full_class_name = class_name
                    self.source_code_index[full_class_name] = file_path

    def get_class_path(self, class_name):
        """
        Returns the file path of a class.
        """
        return self.source_code_index.get(class_name)

    def parse_manifest(self):
        """
        Parses the AndroidManifest.xml file from the decompiled output.
        """
        manifest_path = os.path.join(self.output_dir, "resources", "AndroidManifest.xml")
        if not os.path.exists(manifest_path):
            print(f"AndroidManifest.xml not found in {self.output_dir}")
            return None

        try:
            tree = ET.parse(manifest_path)
            return tree.getroot()
        except ET.ParseError as e:
            print(f"Failed to parse AndroidManifest.xml: {e}")
            return None

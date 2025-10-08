from vector_base import Vector
from constants import *
import os
import json
import re
import requests
from cache_manager import CacheManager

class Vector(Vector):
    OSV_API_URL = "https://api.osv.dev/v1/query"
    def __init__(self, writer, apk, vm, vm_analysis, decompiler, call_graph, native_analyzer, args, config, filtering_engine):
        super().__init__(writer, apk, vm, vm_analysis, decompiler, call_graph, native_analyzer, args, config, filtering_engine)
        self.load_library_db()

    def load_library_db(self):
        db_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'library_database.json')
        try:
            with open(db_path, 'r') as f:
                self.library_db = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            # Silently fail if db is not found or corrupt
            pass

    def analyze(self) -> None:
        if not self.library_db:
            return # Cannot run without the library database

        identified_libs = self.identify_libraries_and_versions()
        if not identified_libs:
            return

        vulnerabilities = self.check_for_vulnerabilities(identified_libs)

        if vulnerabilities:
            self.writer.startWriter("VULNERABLE_DEPENDENCIES", LEVEL_CRITICAL, "Vulnerable Third-Party Libraries Found",
                                    "The application uses third-party libraries with known vulnerabilities. Update them to a secure version.",
                                    ["Security", "Dependency"], vector_name=self.vector_name,
                                    suggestion="Regularly scan dependencies and update libraries to their latest stable and secure versions to mitigate known vulnerabilities.",
                                    confidence=5, risk="Critical")
            for lib_info, vulns in vulnerabilities.items():
                self.writer.write(f"Library: {lib_info}")
                for vuln in vulns:
                    self.writer.write(f"  - ID: {vuln['id']}")
                    self.writer.write(f"    Summary: {vuln['summary']}")
                    self.writer.write(f"    Details: {vuln.get('details', 'N/A')[:200]}...")

    def identify_libraries_and_versions(self) -> dict:
        identified = {}
        all_classes = self.analysis.get_classes()
        for class_obj in all_classes:
            class_name = self.simplifyClassPath(class_obj.name)
            for prefix, lib_info in self.library_db.items():
                if class_name.startswith(prefix):
                    if prefix not in identified:
                        identified[prefix] = {"version": None, "osv_package": lib_info}

        # Heuristic to find versions from pom.properties
        for prefix, lib_data in identified.items():
            try:
                group_id, artifact_id = lib_data['osv_package']['name'].split(':')
                pom_path = f"META-INF/maven/{group_id}/{artifact_id}/pom.properties"
                file_content = self.apk.get_file(pom_path).decode('utf-8')
                match = re.search(r"^version=(.*)$", file_content, re.MULTILINE)
                if match:
                    identified[prefix]["version"] = match.group(1).strip()
            except:
                continue # File not found or parsing error
        return identified

    def check_for_vulnerabilities(self, libraries: dict) -> dict:
        vulnerabilities = {}
        cache_manager = CacheManager(os.path.join(os.path.expanduser("~"), ".matrisks_cache"))

        for prefix, lib_data in libraries.items():
            lib_identifier = f"{lib_data['osv_package']['name']}:{lib_data['version'] or 'Unknown'}"
            cached_result = cache_manager.get(lib_identifier)

            if cached_result:
                vulnerabilities[lib_identifier] = cached_result
                continue

            query = {"package": lib_data['osv_package']}
            if lib_data['version']:
                query["version"] = lib_data['version']
            
            try:
                response = requests.post(self.OSV_API_URL, data=json.dumps(query), timeout=15)
                if response.status_code == 200:
                    result = response.json()
                    if result and 'vulns' in result:
                        vulnerabilities[lib_identifier] = result['vulns']
                        cache_manager.set(lib_identifier, result['vulns'])
            except requests.RequestException:
                pass
        return vulnerabilities

    def simplifyClassPath(self, class_name):
        if class_name.startswith('L') and class_name.endswith(';'):
            return class_name[1:-1].replace('/', '.')
        return class_name.replace('/', '.')

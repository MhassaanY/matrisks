print("Executing matrisks.py...")
import hashlib
import importlib
import platform
import random
import time
import traceback
import json
import os
from datetime import datetime, timezone
from zipfile import BadZipfile
import argparse
from androguard import misc
import persist
import vector_base
import vectors
from writer import *
from scan_manager import ScanManager
from constants import ENABLE_EXCLUDE_CLASSES, STR_REGEXP_TYPE_EXCLUDE_CLASSES

ANALYZE_MODE_SINGLE = "single"
ANALYZE_MODE_MASSIVE = "massive"
ANALYZE_ENGINE_BUILD_DEFAULT = 1  # Analyze Engine(use only number)

DIRECTORY_APK_FILES = ""  # "APKs/"

LINE_MAX_OUTPUT_CHARACTERS_WINDOWS = 160  # 100
LINE_MAX_OUTPUT_CHARACTERS_LINUX = 160
LINE_MAX_OUTPUT_INDENT = 20



import yaml
import requests
import zipfile
import io
from cache_manager import CacheManager
from engines import FilteringEngine
import native_analyzer
import decompiler

# Simple CallGraph stub class
class CallGraph:
    """Simple call graph placeholder for compatibility"""
    def __init__(self, dx):
        self.dx = dx


def _update_osv_cache():
    print("Updating local OSV cache...")
    osv_zip_url = "https://osv-vulnerabilities.storage.googleapis.com/Maven/all.zip"
    try:
        response = requests.get(osv_zip_url, stream=True)
        if response.status_code == 200:
            with zipfile.ZipFile(io.BytesIO(response.content)) as z:
                cache_manager = CacheManager(os.path.join(os.path.expanduser("~"), ".matrisks_cache"))
                for filename in z.namelist():
                    if filename.endswith('.json'):
                        with z.open(filename) as f:
                            data = json.load(f)
                            package_name = data.get("package", {}).get("name")
                            if package_name:
                                cache_manager.set(package_name, data.get("vulns"))
            print("OSV cache update complete.")
        else:
            print(f"Failed to download OSV database. Status code: {response.status_code}")
    except requests.RequestException as e:
        print(f"Failed to download OSV database: {e}")


def parseArgument(parser):
    parser.add_argument("-f", "--apk_file", help="APK File to analyze", type=str, required=False)
    parser.add_argument("-m", "--analyze_mode", help="Specify \"single\"(default) or \"massive\"", type=str,
                        required=False, default=ANALYZE_MODE_SINGLE)
    parser.add_argument("-b", "--analyze_engine_build", help="Analysis build number.", type=int, required=False,
                        default=ANALYZE_ENGINE_BUILD_DEFAULT)
    parser.add_argument("-t", "--analyze_tag", help="Analysis tag to uniquely distinguish this time of analysis.",
                        type=str, required=False, default=None)
    parser.add_argument("-e", "--extra",
                        help="1)Do not check(default)  2)Check  security class names, method names and native methods",
                        type=int, required=False, default=1)
    parser.add_argument("-c", "--line_max_output_characters",
                        help="Setup the maximum characters of analysis output in a line", type=int, required=False)
    parser.add_argument("--config", help="Path to the configuration file (matrisks.yml)", type=str, default="matrisks.yml")
    
    parser.add_argument("-s", "--store_analysis_result_in_db",
                        help="Specify this argument if you want to store the analysis result in MongoDB. Please add this argument if you have MongoDB connection.",
                        action="store_true")
    parser.add_argument("-v", "--show_vector_id",
                        help="Specify this argument if you want to see the Vector ID for each vector.",
                        action="store_true")
    parser.add_argument("-d", "--debug_vector",
                        help="Specify this argument if you want to only load a specific vector.",
                        type=str, required=False, default=None)
    parser.add_argument("-l", "--list_vectors",
                        help="Specify this argument if you want to list the defined vectors.",
                        action="store_true")
    parser.add_argument("--jadx-path", help="Path to the jadx executable", type=str, default="jadx")
    parser.add_argument("--update-osv-cache", help="Update the local OSV cache", action="store_true")
    parser.add_argument("--output-json", help="Path to save the JSON report", type=str, default=None)


    args = parser.parse_args()
    return args


def isNullOrEmptyString(input_string, strip_whitespaces=False):
    if input_string is None:
        return True
    if strip_whitespaces:
        if input_string.strip() == "":
            return True
    else:
        if input_string == "":
            return True
    return False


def get_unique_hash(writer, error_id=None):
    """Generates a unique hash for the analysis."""
    package_name = writer.getInf("package_name", "pkg")
    file_sha256 = writer.getInf("file_sha256", "sha256")
    timestamp = str(time.time())
    random_num = str(random.randrange(10000000, 99999999))

    if error_id:
        original_string = f"{error_id}-{file_sha256}-{timestamp}-{random_num}"
    else:
        original_string = f"{package_name}-{file_sha256}-{timestamp}-{random_num}"

    return hashlib.sha512(original_string.encode()).hexdigest()

def get_hashes_by_filename(filename):
    md5 = hashlib.md5()
    sha1 = hashlib.sha1()
    sha256 = hashlib.sha256()
    sha512 = hashlib.sha512()
    with open(filename, 'rb') as f:
        while chunk := f.read(8192):
            md5.update(chunk)
            sha1.update(chunk)
            sha256.update(chunk)
            sha512.update(chunk)
    return md5.hexdigest(), sha1.hexdigest(), sha256.hexdigest(), sha512.hexdigest()


class ExpectedException(Exception):
    def __init__(self, err_id, message):
        self.err_id = err_id
        self.message = message

    def __str__(self):
        return "[" + self.err_id + "] " + self.message

    def get_err_id(self):
        return self.err_id

    def get_err_message(self):
        return self.message


def _extract_apk_info(writer, a, apk_Path):
    package_name = a.get_package()

    if isNullOrEmptyString(package_name, True):
        raise ExpectedException("package_name_empty", "Package name is empty (File: " + apk_Path + ").")

    writer.writeInf("platform", "Android", "Platform")
    writer.writeInf("package_name", str(package_name), "Package Name")

    
    if not isNullOrEmptyString(a.get_androidversion_name()):
        try:
            writer.writeInf("package_version_name", str(a.get_androidversion_name()), "Package Version Name")
        except:
            writer.writeInf("package_version_name", a.get_androidversion_name().encode('ascii', 'ignore'),
                            "Package Version Name")

    if not isNullOrEmptyString(a.get_androidversion_code()):
        
        
        try:
            writer.writeInf("package_version_code", int(a.get_androidversion_code()), "Package Version Code")
        except ValueError:
            writer.writeInf("package_version_code", a.get_androidversion_code(), "Package Version Code")

    if len(a.get_dex()) == 0:
        raise ExpectedException("classes_dex_not_in_apk",
                                "Broken APK file. \"classes.dex\" file not found (File: " + apk_Path + ").")

    try:
        str_min_sdk_version = a.get_min_sdk_version()
        if (str_min_sdk_version is None) or (str_min_sdk_version == ""):
            raise ValueError
        else:
            int_min_sdk = int(str_min_sdk_version)
            writer.writeInf("minSdk", int_min_sdk, "Min Sdk")
    except ValueError:
        
        
        writer.writeInf("minSdk", 1, "Min Sdk")
        int_min_sdk = 1

    try:
        str_target_sdk_version = a.get_target_sdk_version()
        if (str_target_sdk_version is None) or (str_target_sdk_version == ""):
            raise ValueError
        else:
            int_target_sdk = int(str_target_sdk_version)
            writer.writeInf("targetSdk", int_target_sdk, "Target Sdk")
    except ValueError:
        
        
        int_target_sdk = int_min_sdk

    md5, sha1, sha256, sha512 = get_hashes_by_filename(apk_Path)
    writer.writeInf("file_md5", md5, "MD5   ")
    writer.writeInf("file_sha1", sha1, "SHA1  ")
    writer.writeInf("file_sha256", sha256, "SHA256")
    writer.writeInf("file_sha512", sha512, "SHA512")

def _run_vectors(writer, a, d, dx, decompiler_obj, call_graph_obj, native_analyzer_obj, args, config):
    writer.update_analyze_status("loading_vectors")

    enabled_vectors = config.get('vectors', {}).get('enabled', [])

    print("Loaded vectors:")
    for vector_name in enabled_vectors:
        try:
            importlib.import_module(f'vectors.{vector_name}')
            print(vector_name)
        except ImportError:
            print(f"Warning: Could not import vector '{vector_name}'. It will be skipped.")

    writer.update_analyze_status("checking_vectors")
    
    native_analysis_results = native_analyzer_obj.analyze()

    filtering_engine = FilteringEngine(ENABLE_EXCLUDE_CLASSES, STR_REGEXP_TYPE_EXCLUDE_CLASSES)
    
    # In androguard 4.x, d is a list of DEX objects. Use the first one for vectors.
    # Most apps have a single classes.dex, but some have multiple.
    vm = d[0] if isinstance(d, list) and len(d) > 0 else d
    
    for vector_name in enabled_vectors:
        print(f"Running vector: {vector_name}")
        try:
            vector_module = importlib.import_module(f"vectors.{vector_name}")
            vector_instance = vector_module.Vector(writer, a, vm, dx, decompiler_obj, call_graph_obj, native_analyzer_obj, args, config, filtering_engine)
            vector_instance.analyze()
        except Exception as e:
            print(f"Error running vector {vector_name}: {e}")
            import traceback
            traceback.print_exc()

def _initialize_analysis(writer, args):
    # StopWatch: Counting execution time...
    start_time = datetime.now()

    if args.line_max_output_characters is None:
        if platform.system().lower() == "windows":
            args.line_max_output_characters = LINE_MAX_OUTPUT_CHARACTERS_WINDOWS - LINE_MAX_OUTPUT_INDENT
        else:
            args.line_max_output_characters = LINE_MAX_OUTPUT_CHARACTERS_LINUX - LINE_MAX_OUTPUT_INDENT

    writer.writeInf_ForceNoPrint("analyze_mode", args.analyze_mode)
    writer.writeInf_ForceNoPrint("analyze_engine_build", args.analyze_engine_build)
    if args.analyze_tag:
        writer.writeInf_ForceNoPrint("analyze_tag", args.analyze_tag)

    APK_FILE_NAME_STRING = DIRECTORY_APK_FILES + args.apk_file
    apk_Path = APK_FILE_NAME_STRING  # ".apk"

    decompiler_obj = decompiler.Decompiler(apk_Path, writer.decompiled_source_path)

    if not os.path.isfile(apk_Path):
        raise ExpectedException("apk_file_not_exist", "APK file not exist (File: " + apk_Path + ").")

    decompiler_obj.decompile(args.jadx_path)
    

    if args.store_analysis_result_in_db:
        try:
            importlib.util.find_spec('pymongo')
            found_pymongo_lib = True
        except ImportError:
            found_pymongo_lib = False

        if not found_pymongo_lib:
            pass

    
    apk_filepath_absolute = os.path.abspath(apk_Path)

    
    writer.writeInf_ForceNoPrint("apk_filepath_absolute", apk_filepath_absolute)

    apk_file_size = float(os.path.getsize(apk_filepath_absolute)) / (1024 * 1024)
    writer.writeInf_ForceNoPrint("apk_file_size", apk_file_size)

    writer.update_analyze_status("loading_apk")

    writer.writeInf_ForceNoPrint("time_starting_analyze", datetime.now(timezone.utc))

    a, d, dx = misc.AnalyzeAPK(apk_Path)

    call_graph_obj = CallGraph(dx)

    writer.update_analyze_status("starting_apk")
    return start_time, a, d, dx, decompiler_obj, call_graph_obj, apk_Path

def _generate_analysis_index(a, d, dx, output_path):
    print("Generating analysis index...")
    index = {
        "classes": [],
        "strings": [],
        "call_graph": {}
    }

    for vm in d:
        for cls in vm.get_classes():
            class_data = {
                "name": cls.name,
                "methods": [],
                "fields": []
            }
            for method in cls.get_methods():
                class_data["methods"].append({
                    "name": method.name,
                    "descriptor": method.get_descriptor(),
                    "access": method.get_access_flags_string(),
                })
            for field in cls.get_fields():
                class_data["fields"].append({
                    "name": field.get_name(),
                    "descriptor": field.get_descriptor(),
                    "access": field.get_access_flags_string(),
                })
            index["classes"].append(class_data)

    for s in dx.get_strings():
        index["strings"].append(s.get_value())

    for method in dx.get_methods():
        method_key = method.get_method().get_class_name() + "->" + method.get_method().name + method.get_method().get_descriptor()
        index["call_graph"][method_key] = []
        for _, call, _ in method.get_xref_to():
            # In androguard 4.x, call is a MethodAnalysis object, need to get the actual method
            call_method = call.get_method() if hasattr(call, 'get_method') else call
            index["call_graph"][method_key].append(
                call_method.get_class_name() + "->" + call_method.get_name() + call_method.get_descriptor()
            )

    with open(output_path, 'w') as f:
        json.dump(index, f, indent=2)
    print(f"Analysis index saved to {output_path}")

def __analyze(writer, args, config):
    start_time, a, d, dx, decompiler_obj, call_graph_obj, apk_Path = _initialize_analysis(writer, args)

    _extract_apk_info(writer, a, apk_Path)

    writer.update_analyze_status("starting_matrisks")

    analysis_start = datetime.now()

    index_path = os.path.join(writer.staging_dir, "analysis_index.json")
    _generate_analysis_index(a, d, dx, index_path)

    native_analyzer_obj = native_analyzer.NativeAnalyzer(a, writer.staging_dir)
    _run_vectors(writer, a, d, dx, decompiler_obj, call_graph_obj, native_analyzer_obj, args, config)

    writer.completeWriter()
    writer.writeInf_ForceNoPrint("vector_total_count", writer.get_total_vector_count())

    stop_time = datetime.now()
    total_elapsed_time = stop_time - start_time
    analysis_time = stop_time - analysis_start
    vm_loading_time = analysis_start - start_time

    writer.writeInf_ForceNoPrint("time_total", total_elapsed_time.total_seconds())
    writer.writeInf_ForceNoPrint("time_analyze", analysis_time.total_seconds())
    writer.writeInf_ForceNoPrint("time_loading_vm", vm_loading_time.total_seconds())

    writer.update_analyze_status("success")
    writer.writeInf_ForceNoPrint("time_finish_analyze", datetime.now(timezone.utc))


def _generate_reports(writer, args):
    """Generate comprehensive reports using new v2 reporting system"""
    print("\n" + "="*80)
    print("Generating Comprehensive Reports...")
    print("="*80)
    
    # Legacy text output (if needed)
    if REPORT_OUTPUT == "print":
        writer.show(args)
    elif REPORT_OUTPUT == "print_and_file":
        writer.show(args)
        writer.save_result_to_file(args)

    # Import new reporting system
    try:
        from report_generator_v2 import MatrisksReportGeneratorV2
        
        # Prepare data for new reporting system
        scan_data = writer.getInfDict()  # Get all metadata
        
        # Add APK file path to scan_data
        scan_data['apk_file'] = args.apk_file
        
        apk_info = {
            'app_name': scan_data.get('package_name', 'N/A'),
            'package_name': scan_data.get('package_name', 'N/A'),
            'version_name': scan_data.get('package_version_name', 'N/A'),
            'version_code': scan_data.get('package_version_code', 'N/A'),
            'min_sdk': scan_data.get('minSdk', 'N/A'),
            'target_sdk': scan_data.get('targetSdk', 'N/A'),
            'file_size_mb': scan_data.get('apk_file_size', 0),
            'md5': scan_data.get('file_md5', ''),
            'sha1': scan_data.get('file_sha1', ''),
            'sha256': scan_data.get('file_sha256', ''),
            'sha512': scan_data.get('file_sha512', ''),
        }
        
        # Get vector results
        vector_results = writer.get_vector_results()
        
        # Create report generator
        report_gen = MatrisksReportGeneratorV2(scan_data, apk_info, vector_results)
        
        # Generate all reports
        print("\n📊 Generating enhanced reports...")
        
        # JSON Report
        if args.output_json:
            json_report_path = args.output_json
        else:
            json_report_path = os.path.join(writer.staging_dir, "report.json")
        report_gen.save_json_report(json_report_path)
        
        # CSV Report
        csv_report_path = os.path.join(writer.staging_dir, "report.csv")
        report_gen.save_csv_report(csv_report_path)
        
        # HTML Report
        html_report_path = os.path.join(writer.staging_dir, "report.html")
        report_gen.save_html_report(html_report_path)
        
        # PDF generation is not currently supported
        # Users can convert HTML to PDF using browser or external tools if needed
        
        print("\n" + "="*80)
        print("✓ All reports generated successfully!")
        print(f"📁 Report directory: {writer.staging_dir}")
        print("="*80 + "\n")
        
    except Exception as report_err:
        print(f"\n⚠️  Error generating v2 reports: {report_err}")
        print("Falling back to legacy reporting...")
        
        # Fallback to legacy reporting
        if args.output_json:
            json_report_path = args.output_json
        else:
            json_report_path = os.path.join(writer.staging_dir, "report.json")
        writer.save_json_report(json_report_path)
        
        csv_report_path = os.path.join(writer.staging_dir, "report.csv")
        writer.save_csv_report(csv_report_path)


def _validate_config(config):
    schema = {
        'vectors': {
            'type': 'dict',
            'schema': {
                'enabled': {'type': 'list', 'schema': {'type': 'str'}},
            }
        },
        'hardcoded_secrets': {
            'type': 'dict',
            'schema': {
                'wordlist_path': {'type': 'str'},
                'entropy_threshold': {'type': 'float'},
            }
        }
    }

    def validate(config, schema, path=''):
        for key, rules in schema.items():
            if key not in config:
                continue

            if not isinstance(config[key], eval(rules['type'])):
                raise ValueError(f"Invalid type for {path}{key}. Expected {rules['type']}, got {type(config[key])}.")

            if rules['type'] == 'dict' and 'schema' in rules:
                validate(config[key], rules['schema'], f"{path}{key}.")
            elif rules['type'] == 'list' and 'schema' in rules:
                for i, item in enumerate(config[key]):
                    if not isinstance(item, eval(rules['schema']['type'])):
                        raise ValueError(f"Invalid type for {path}{key}[{i}]. Expected {rules['schema']['type']}, got {type(item)}.")

    validate(config, schema)

def _resolve_string(method, register):
    """Resolves a constant string from a register."""
    # This is a very basic implementation and only handles simple cases.
    # A more advanced implementation would require a full-fledged symbolic execution engine.
    for ins in method.get_instructions():
        if ins.get_name() == 'const-string' and ins.get_output().startswith(register):
            return ins.get_operands()[1]
    return None

def main():
    parser = argparse.ArgumentParser(description='Matrisks Framework - Android App Security Vulnerability Scanner')
    args = parseArgument(parser)

    if args.update_osv_cache:
        _update_osv_cache()
        return

    try:
        with open(args.config, 'r') as f:
            config = yaml.safe_load(f)
            _validate_config(config)
    except (FileNotFoundError, yaml.YAMLError, ValueError) as e:
        print(f"Error loading configuration file {args.config}: {e}")
        return

    
    if args.list_vectors:
        print("The following vector tags are defined")
        loaded_vector_classes = []
        file_list = os.listdir(os.path.dirname(vectors.__file__))
        for file_name in file_list:
            if file_name.endswith('.py') and file_name != '__init__.py':
                loaded_vector_classes.append(importlib.import_module('vectors.' + file_name.replace('.py', '')))

        loaded_vector_classes: [vector_base.Vector]
        for vector_class in loaded_vector_classes:
            print(vector_class.Vector.tags, vector_class.Vector.description)
        return
    elif args.apk_file is None:
        parser.error("APK name is required")

    scan_manager = ScanManager()
    staging_dir = scan_manager.create_scan_environment()

    writer = Writer(staging_dir)

    try:
        writer.writePlainInf("**********************************************************************************************\n**           Matrisks Framework - Android App Security Vulnerability Scanner               **\n**********************************************************************************************")

        __analyze(writer, args, config)

        analyze_signature = get_unique_hash(writer)
        writer.writeInf_ForceNoPrint("signature_unique_analyze",
                                     analyze_signature)
        writer.append_to_file_io_information_output_list("Analyze Signature: " + analyze_signature)
        writer.append_to_file_io_information_output_list(
            "------------------------------------------------------------------------------------------------")

    except ExpectedException as err_expected:

        writer.update_analyze_status("fail")

        writer.writeInf_ForceNoPrint("analyze_error_type_expected", True)
        writer.writeInf_ForceNoPrint("analyze_error_time", datetime.now(timezone.utc))
        writer.writeInf_ForceNoPrint("signature_unique_analyze",
                                     get_unique_hash(writer))
        writer.writeInf_ForceNoPrint("signature_unique_exception", get_unique_hash(writer, error_id=err_expected.get_err_id()))

        # if DEBUG:
        #     print(err_expected)

    except BadZipfile as zip_err:

        writer.update_analyze_status("fail")

        writer.writeInf_ForceNoPrint("analyze_error_detail_traceback", traceback.format_exc())

        writer.writeInf_ForceNoPrint("analyze_error_type_expected", True)
        writer.writeInf_ForceNoPrint("analyze_error_time", datetime.now(timezone.utc))
        writer.writeInf_ForceNoPrint("signature_unique_analyze",
                                     get_unique_hash(writer))
        writer.writeInf_ForceNoPrint("signature_unique_exception", get_unique_hash(writer, error_id="fail_to_unzip_apk_file"))

        # if DEBUG:
        #     print("[Unzip Error]")
        #     traceback.print_exc()

    except Exception as err:

        writer.update_analyze_status("fail")

        writer.writeInf_ForceNoPrint("analyze_error_detail_traceback", traceback.format_exc())

        writer.writeInf_ForceNoPrint("analyze_error_type_expected", False)
        writer.writeInf_ForceNoPrint("analyze_error_time", datetime.now(timezone.utc))
        writer.writeInf_ForceNoPrint("analyze_error_id", str(type(err)))
        writer.writeInf_ForceNoPrint("analyze_error_message", str(err))

        writer.writeInf_ForceNoPrint("signature_unique_analyze",
                                     get_unique_hash(writer))
        writer.writeInf_ForceNoPrint("signature_unique_exception", get_unique_hash(writer, error_id=str(type(err))))

        # Temporarily enable error printing for debugging
        print(f"ERROR: Analysis failed with exception: {err}")
        traceback.print_exc()

    finally:
        if args.store_analysis_result_in_db:
            persist.__persist_db(writer, args)

        print("Before generating reports...")
        _generate_reports(writer, args)

        scan_manager.finalize_scan()


if __name__ == "__main__":
    main()

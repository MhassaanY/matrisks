import hashlib
import importlib
import platform
import random
import time
import traceback
from datetime import datetime, timezone
from zipfile import BadZipfile
import argparse
from androguard import misc
import persist
import vector_base
import vectors
from writer import *
from scan_manager import ScanManager

ANALYZE_MODE_SINGLE = "single"
ANALYZE_MODE_MASSIVE = "massive"
ANALYZE_ENGINE_BUILD_DEFAULT = 1  # Analyze Engine(use only number)

DIRECTORY_APK_FILES = ""  # "APKs/"

LINE_MAX_OUTPUT_CHARACTERS_WINDOWS = 160  # 100
LINE_MAX_OUTPUT_CHARACTERS_LINUX = 160
LINE_MAX_OUTPUT_INDENT = 20



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


def get_hash_scanning(writer):
    # signature = hash(package_name(default="") + "-" + file_sha256(default="") + "-" + timestamp_long + "-" + random_number_length8)
    # use "-" because aaa-bbb.com is not a valid domain name
    tmp_original = writer.getInf("package_name", "pkg") + "-" + writer.getInf("file_sha256", "sha256") + "-" + str(
        time.time()) + "-" + str(random.randrange(10000000, 99999999))
    tmp_hash = hashlib.sha512(tmp_original.encode()).hexdigest()
    return tmp_hash


def get_hash_exception(writer):
    # signature = hash(analyze_error_id(default="") + "-" + file_sha256(default="") + "-" + timestamp_long + "-" + random_number_length8)
    tmp_original = writer.getInf("analyze_error_id", "err") + "-" + writer.getInf("file_sha256", "sha256") + "-" + str(
        time.time()) + "-" + str(random.randrange(10000000, 99999999))
    tmp_hash = hashlib.sha512(tmp_original.encode()).hexdigest()
    return tmp_hash


def get_hashes_by_filename(filename):
    with open(filename, 'r', encoding='ISO-8859-1') as f:
        data = f.read().encode()
        md5 = hashlib.md5(data).hexdigest()
        sha1 = hashlib.sha1(data).hexdigest()
        sha256 = hashlib.sha256(data).hexdigest()
        sha512 = hashlib.sha512(data).hexdigest()
    return md5, sha1, sha256, sha512


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


def __analyze(writer, args):
    

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
    apk_Path = APK_FILE_NAME_STRING  # + ".apk"

    if not os.path.isfile(apk_Path):
        raise ExpectedException("apk_file_not_exist", "APK file not exist (File: " + apk_Path + ").")

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

    # Handle androguard 4.x compatibility - AnalyzeAPK returns generator
    try:
        a, d, dx = misc.AnalyzeAPK(apk_Path)
    except TypeError:
        # For newer androguard versions that return generator
        result = misc.AnalyzeAPK(apk_Path)
        if hasattr(result, '__iter__') and not isinstance(result, (str, bytes)):
            a, d, dx = list(result)
        else:
            a, d, dx = result

    writer.update_analyze_status("starting_apk")

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

    md5, sha1, sha256, sha512 = get_hashes_by_filename(APK_FILE_NAME_STRING)
    writer.writeInf("file_md5", md5, "MD5   ")
    writer.writeInf("file_sha1", sha1, "SHA1  ")
    writer.writeInf("file_sha256", sha256, "SHA256")
    writer.writeInf("file_sha512", sha512, "SHA512")

    writer.update_analyze_status("starting_matrisks")

    analysis_start = datetime.now()

    writer.update_analyze_status("loading_vectors")

    loaded_vector_classes = list()

    print("Loaded vectors:")
    file_list = os.listdir(os.path.dirname(vectors.__file__))
    for file_name in file_list:
        if file_name.endswith('.py') and file_name != '__init__.py':
            loaded_vector_classes.append(importlib.import_module('vectors.' + file_name.replace('.py', '')))
            print(file_name.replace('.py', ''))

    writer.update_analyze_status("checking_vectors")
    loaded_vector_classes: [vector_base.Vector]
    for vector_class in loaded_vector_classes:
        if args.debug_vector is None or args.debug_vector in vector_class.Vector.tags:
            print("Running " + vector_class.__name__ + " analysis.")
            vector_class.Vector(writer, a, d, dx, args, int_min_sdk, int_target_sdk).analyze()

    

    
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


import graphical_report_generator


def main():
    parser = argparse.ArgumentParser(description='Matrisks Framework - Android App Security Vulnerability Scanner')
    args = parseArgument(parser)

    
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

        
        __analyze(writer, args)

        analyze_signature = get_hash_scanning(writer)
        writer.writeInf_ForceNoPrint("signature_unique_analyze",
                                     analyze_signature)  
        writer.append_to_file_io_information_output_list("Analyze Signature: " + analyze_signature)
        writer.append_to_file_io_information_output_list(
            "------------------------------------------------------------------------------------------------")

    except ExpectedException as err_expected:

        writer.update_analyze_status("fail")

        writer.writeInf_ForceNoPrint("analyze_error_type_expected", True)
        writer.writeInf_ForceNoPrint("analyze_error_time", datetime.now(timezone.utc))
        writer.writeInf_ForceNoPrint("analyze_error_id", err_expected.get_err_id())
        writer.writeInf_ForceNoPrint("analyze_error_message", err_expected.get_err_message())

        writer.writeInf_ForceNoPrint("signature_unique_analyze",
                                     get_hash_scanning(writer))  
        writer.writeInf_ForceNoPrint("signature_unique_exception", get_hash_exception(writer))

        if DEBUG:
            print(err_expected)

    except BadZipfile as zip_err:  

        writer.update_analyze_status("fail")

        
        writer.writeInf_ForceNoPrint("analyze_error_detail_traceback", traceback.format_exc())

        writer.writeInf_ForceNoPrint("analyze_error_type_expected", True)
        writer.writeInf_ForceNoPrint("analyze_error_time", datetime.now(timezone.utc))
        writer.writeInf_ForceNoPrint("analyze_error_id", "fail_to_unzip_apk_file")
        writer.writeInf_ForceNoPrint("analyze_error_message", str(zip_err))

        writer.writeInf_ForceNoPrint("signature_unique_analyze",
                                     get_hash_scanning(writer))  
        writer.writeInf_ForceNoPrint("signature_unique_exception", get_hash_exception(writer))

        if DEBUG:
            print("[Unzip Error]")
            traceback.print_exc()

    except Exception as err:

        writer.update_analyze_status("fail")

        
        writer.writeInf_ForceNoPrint("analyze_error_detail_traceback", traceback.format_exc())

        writer.writeInf_ForceNoPrint("analyze_error_type_expected", False)
        writer.writeInf_ForceNoPrint("analyze_error_time", datetime.now(timezone.utc))
        writer.writeInf_ForceNoPrint("analyze_error_id", str(type(err)))
        writer.writeInf_ForceNoPrint("analyze_error_message", str(err))

        writer.writeInf_ForceNoPrint("signature_unique_analyze",
                                     get_hash_scanning(writer))  
        writer.writeInf_ForceNoPrint("signature_unique_exception", get_hash_exception(writer))

        if DEBUG:
            traceback.print_exc()

    
    if args.store_analysis_result_in_db:
        persist.__persist_db(writer, args)

    if writer.get_analyze_status() == "success":

        if REPORT_OUTPUT == "print":
            writer.show(args)
        elif REPORT_OUTPUT == "file":
            report_file_path = persist.__persist_file(writer, args)
            if report_file_path:
                html_report_path = os.path.join(writer.staging_dir, "report.html")
                graphical_report_generator.main(report_file_path, html_report_path)
        elif REPORT_OUTPUT == "print_and_file":
            writer.show(args)
            report_file_path = persist.__persist_file(writer, args)
            if report_file_path:
                html_report_path = os.path.join(writer.staging_dir, "report.html")
                graphical_report_generator.main(report_file_path, html_report_path)

    scan_manager.finalize_scan()


if __name__ == "__main__":
    main()
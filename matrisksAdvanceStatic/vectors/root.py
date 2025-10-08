import re
import staticDVM
from vector_base import Vector
from constants import *

class Vector(Vector):
    def __init__(self, writer, apk, vm, vm_analysis, decompiler, call_graph, native_analyzer, args, config, filtering_engine):
        super().__init__(writer, apk, vm, vm_analysis, decompiler, call_graph, native_analyzer, args, config, filtering_engine)
    description = "Checks for attempts to gain root privileges or detect rooted devices."
    tags = ["ROOT_DETECTION", "ROOT_EXECUTION"]

    def analyze(self) -> None:
        self.check_for_root_execution()
        self.check_for_root_detection_strings()

    def check_for_root_execution(self) -> None:
        """Checks for explicit calls to Runtime.exec('su')."""
        vulnerable_paths = []
        exec_paths = self.analysis.find_methods(
            classname="Ljava/lang/Runtime;", 
            methodname="exec", 
            descriptor="(Ljava/lang/String;)Ljava/lang/Process;"
        )

        for trace in staticDVM.trace_register_value_by_param_in_method_class_analysis_list(exec_paths):
            command = trace.getResult()[1]
            if command and isinstance(command, str) and command.strip().startswith("su"):
                vulnerable_paths.append(trace.getPath())

        if vulnerable_paths:
            self.writer.startWriter("ROOT_EXECUTION", LEVEL_CRITICAL, "Application Attempts to Execute as Root",
                               "The application attempts to execute the 'su' command, indicating an attempt to gain root privileges.",
                               ["Command", "Root"], vector_name=self.vector_name,
                               suggestion="Ensure that any attempt to gain root privileges is intended and handled securely. Unauthorized root access can lead to a full compromise of the device.",
                               confidence=5, risk="Critical")
            for path in vulnerable_paths:
                self.writer.write("'su' command executed in:")
                self.writer.show_Path(path, indention_space_count=4)

    def check_for_root_detection_strings(self) -> None:
        """Checks for strings that indicate the app is looking for root binaries."""
        # This is a heuristic check for strings that are commonly used to detect a rooted environment.
        # It's less precise than finding exec calls, but still valuable.
        regex_excluded_class_names = re.compile(STR_REGEXP_TYPE_EXCLUDE_CLASSES)
        found_strings = []

        # Look for common root package names and su binaries
        for string_analysis in self.analysis.find_strings(r"(com\.noshufou\.android\.su|com\.thirdparty\.superuser|eu\.chainfire\.supersu|/system/bin/su|/system/xbin/su)"):
            if not all([regex_excluded_class_names.match(xref_class.name)
                        for xref_class, xref_method in string_analysis.get_xref_from()]):
                found_strings.append(string_analysis)

        if found_strings:
            self.writer.startWriter("ROOT_DETECTION", LEVEL_NOTICE, "Root Detection Strings Found",
                               "The application contains strings related to root access or root-management packages. This indicates the application may be attempting to detect if the device is rooted.",
                               ["Root"], vector_name=self.vector_name,
                               suggestion="This is often done for security reasons (e.g., to disable features on a rooted device). Verify this is the intended behavior.",
                               confidence=5, risk="Info")
            for found_string in found_strings:
                self.writer.write(f"Found potential root detection string: \"{found_string.get_value()}\"")
                self.writer.write("  Used in:")
                self._print_xrefs(found_string, indent=4)

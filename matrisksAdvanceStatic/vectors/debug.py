from vector_base import Vector
from constants import *
try:
    # Try androguard 4.x imports
    from androguard.core import dex as dvm
except ImportError:
    # Fall back to androguard 3.x imports
    from androguard.core.bytecodes import dvm
from timeit import default_timer as timer
import staticDVM

class Vector(Vector):
    def __init__(self, writer, apk, vm, vm_analysis, decompiler, call_graph, native_analyzer, args, config, filtering_engine):
        super().__init__(writer, apk, vm, vm_analysis, decompiler, call_graph, native_analyzer, args, config, filtering_engine)
    description = "Checks if debug mode is enabled, " \
                  "if a debug certificate is present, and " \
                  "if debug mode detection is used"
    tags = ["DEBUGGABLE", "HACKER_DEBUGGABLE_CERT", "HACKER_DEBUGGABLE_CHECK"]

    OPCODES = {
        "iget": 0x52,
        "and-int/lit8": 0xDD,
    }

    def analyze(self) -> None:
        self.check_is_debuggable()
        self.check_has_debuggable_certificate()
        self.check_detects_debuggable()
        self.check_ro_debuggable()
        self.check_anti_debugging()
        self.check_is_debuggable()
        self.check_has_debuggable_certificate()
        self.check_detects_debuggable()
        self.check_ro_debuggable()
        self.check_anti_debugging()

    def check_is_debuggable(self) -> None:
        is_debug_open = self.apk.get_attribute_value('application', 'debuggable') not in (None, "false")
        if is_debug_open:
            self.writer.startWriter("DEBUGGABLE", LEVEL_CRITICAL, "Debug Mode is Enabled",
                                    "The application is debuggable (android:debuggable=\"true\"). This allows attackers to attach a debugger and access sensitive information.",
                                    ["Debug"], vector_name=self.vector_name,
                                    suggestion="Set android:debuggable=\"false\" in the AndroidManifest.xml for all release builds.",
                                    confidence=5, risk="Critical")

        else:
            self.writer.startWriter("DEBUGGABLE", LEVEL_INFO, "Android Debug Mode Checking",
                                    "DEBUG mode is OFF(android:debuggable=\"false\") in AndroidManifest.xml.",
                                    ["Debug"], vector_name=self.vector_name)

    def check_has_debuggable_certificate(self) -> None:
        for cert in self.apk.get_certificates():
            if "Common Name: Android Debug" in cert.issuer.human_friendly:
                self.writer.startWriter("HACKER_DEBUGGABLE_CERT", LEVEL_CRITICAL, "Signed with Debug Certificate",
                                        "The application is signed with a standard Android debug certificate. It should be signed with a unique release certificate.",
                                        ["Debug"], vector_name=self.vector_name,
                                        suggestion="Sign the application with a unique, production-ready release certificate.",
                                        confidence=5, risk="High")
                return

        self.writer.startWriter("HACKER_DEBUGGABLE_CERT", LEVEL_INFO, "Android Debug Certificate Checking",
                                "App is signed with a production certificate. This is good.",
                                ["Debug"], vector_name=self.vector_name)

    def check_detects_debuggable(self) -> None:

        start = timer()
        matches = self._scan_for_debuggable_checks()
        end = timer()
        self.writer.writeInf_ForceNoPrint("time_hacker_debuggable_check", end-start)

        if matches:
            self.writer.startWriter("HACKER_DEBUGGABLE_CHECK", LEVEL_NOTICE,
                                    "Application Checks for Debug Mode",
                                    "The application contains code to check if it is running in debug mode. This is often used as an anti-debugging technique.",
                                    ["Debug", "Hacker"], vector_name=self.vector_name,
                                    suggestion="This is an informational finding. Verify that this check is implemented securely and does not introduce other vulnerabilities.",
                                    confidence=5, risk="Info")

            for method in matches:
                self.writer.write(
                    "%s->%s%s" % (method.get_class_name(), method.get_name(), method.get_descriptor()))
            return

        self.writer.startWriter("HACKER_DEBUGGABLE_CHECK", LEVEL_INFO, "Code for Checking Android Debug Mode",
                                "Did not detect code that checks whether debug mode is enabled",
                                ["Debug", "Hacker"], vector_name=self.vector_name)

    def _scan_for_debuggable_checks(self):
        # Handle both single DEX and list of DEX
        dalvik_list = [self.dalvik] if not isinstance(self.dalvik, list) else self.dalvik
        
        if not any([dalvik for dalvik in dalvik_list
                    if any([i for i in dalvik.get_all_fields()
                                if i.get_list() == ['Landroid/content/pm/ApplicationInfo;', 'I', 'flags']
                            ])
                   ]):
            return []

        return [method_analysis.get_method()
                for method_analysis in self.analysis.get_methods()
                    if not method_analysis.is_external() and \
                        self._scan_method_instructions_for_application_info(method_analysis.get_method().get_instructions())
                ]

    def _scan_method_instructions_for_application_info(self, instructions):
        return any([True
                    for instruction in instructions
                        if instruction.get_op_value() == self.OPCODES["iget"] and \
                            instruction.get_operands()[2][2] == "Landroid/content/pm/ApplicationInfo;->flags I" and \
                            self._does_next_instruction_access_debug_flag(instruction.get_operands()[0], next(instructions))
                    ])

    def _does_next_instruction_access_debug_flag(self, flags_register, instruction):
        operands = instruction.get_operands()
        opcode = instruction.get_op_value()
        if opcode == self.OPCODES["and-int/lit8"] and \
                operands[2] == (dvm.OPERAND_LITERAL, 2) and \
                operands[1] == flags_register:
            return True
        return False

    def check_ro_debuggable(self) -> None:
        """Checks for ro.debuggable system property check."""
        paths = self.analysis.find_methods(
            classname="Landroid/os/SystemProperties;",
            methodname="get",
            descriptor="(Ljava/lang/String;)Ljava/lang/String;"
        )

        if paths:
            for path in staticDVM.get_paths(paths):
                if 'ro.debuggable' in path['src_method'].get_code().get_strings():
                    self.writer.startWriter("ANTI_DEBUG_RO_DEBUGGABLE", LEVEL_NOTICE, "Anti-Debugging Technique Detected",
                                            "The application checks the ro.debuggable system property to detect if it is running on a debuggable build.",
                                            ["Anti_Debug"], vector_name=self.vector_name,
                                            suggestion="This is an informational finding. Verify that this check is implemented securely and does not introduce other vulnerabilities.",
                                            confidence=4, risk="Info")
                    self.writer.write(f"ro.debuggable check found in: {self.writer.simplifyClassPath(path['src_method'].get_class_name())}")
                    return

    def check_anti_debugging(self) -> None:
        """Checks for common anti-debugging techniques."""
        # Check for installation timestamp check
        paths = self.analysis.find_fields(
            fieldname="firstInstallTime",
            fieldtype="J"
        )

        if paths:
            self.writer.startWriter("ANTI_DEBUG_INSTALL_TIME", LEVEL_NOTICE, "Anti-Debugging Technique Detected",
                                    "The application checks the installation timestamp, which can be used to detect if the application is running in an emulator or a testing environment.",
                                    ["Anti_Debug"], vector_name=self.vector_name,
                                    suggestion="This is an informational finding. Verify that this check is implemented securely and does not introduce other vulnerabilities.",
                                    confidence=3, risk="Info")
            for path in staticDVM.get_paths(paths):
                self.writer.write(f"Installation timestamp check found in: {self.writer.simplifyClassPath(path['src_method'].get_class_name())}")
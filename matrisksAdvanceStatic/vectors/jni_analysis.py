from vector_base import Vector
from constants import *

class Vector(Vector):
    description = "Analyzes JNI mappings to identify potential vulnerabilities."
    tags = ["JNI_ANALYSIS"]

    def __init__(self, writer, apk, vm, vm_analysis, decompiler, call_graph, native_analyzer, args, config, filtering_engine):
        super().__init__(writer, apk, vm, vm_analysis, decompiler, call_graph, native_analyzer, args, config, filtering_engine)

    def analyze(self) -> None:
        if not self.native_analyzer:
            return

        native_analysis_results = self.native_analyzer.analyze()

        if native_analysis_results:
            self.writer.startWriter("JNI_MAPPINGS", LEVEL_INFO, "JNI Mappings Found",
                                    "The application uses Java Native Interface (JNI) to call native functions. Review these functions to ensure they are implemented securely.",
                                    ["Native"], vector_name=self.vector_name,
                                    suggestion="Ensure that native functions perform proper input validation and do not expose sensitive data.",
                                    confidence=3, risk="Info")
            for so_file, analysis in native_analysis_results.items():
                if analysis["jni_mappings"]:
                    self.writer.write(f"JNI functions in {so_file}:")
                    for jni_function in analysis["jni_mappings"]:
                        self.writer.write(f"  - {jni_function}")
                        self.analyze_jni_function(jni_function)

    def analyze_jni_function(self, jni_function):
        # Example: Java_com_example_android_insecurebankv2_Crypto_encrypt
        parts = jni_function.split("_")
        if len(parts) < 4:
            return

        class_name = "L" + "/".join(parts[1:-1]) + ";"
        method_name = parts[-1]

        cls = self.analysis.get_class_analysis(class_name)
        if not cls:
            return

        for method in cls.get_methods():
            if method.get_name() == method_name:
                if "Ljava/lang/String;" in method.get_descriptor():
                    self.writer.startWriter("JNI_STRING_ARGUMENT", LEVEL_NOTICE, "JNI Function with String Argument",
                                            f"The JNI function {jni_function} takes a string as an argument. Ensure that this data is handled securely in the native code.",
                                            ["Native", "Data_Leak"], vector_name=self.vector_name,
                                            suggestion="Review the native code to ensure that the string is not logged or stored insecurely.",
                                            confidence=3, risk="Medium")
                if method.get_descriptor().endswith("Ljava/lang/String;"):
                    self.writer.startWriter("JNI_STRING_RETURN", LEVEL_NOTICE, "JNI Function with String Return Value",
                                            f"The JNI function {jni_function} returns a string. Ensure that this data is not sensitive or that it is properly protected.",
                                            ["Native", "Data_Leak"], vector_name=self.vector_name,
                                            suggestion="Review the native code to ensure that the returned string does not contain sensitive data.",
                                            confidence=3, risk="Medium")
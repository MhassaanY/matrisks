from vector_base import Vector
from constants import *

class Vector(Vector):
    description = "Analyzes the use of reflection to identify potential security risks."
    tags = ["REFLECTION_ANALYSIS"]

    def __init__(self, writer, apk, vm, vm_analysis, decompiler, call_graph, native_analyzer, args, config, filtering_engine):
        super().__init__(writer, apk, vm, vm_analysis, decompiler, call_graph, native_analyzer, args, config, filtering_engine)

    def analyze(self) -> None:
        if not self.index:
            return

        self.check_for_reflective_calls()

    def check_for_reflective_calls(self):
        """Finds calls to common reflection methods."""
        reflective_calls = []
        methods_to_check = [
            "Ljava/lang/Class;->forName(Ljava/lang/String;)Ljava/lang/Class;",
            "Ljava/lang/reflect/Method;->invoke(Ljava/lang/Object; [Ljava/lang/Object;)Ljava/lang/Object;",
            "Ljava/lang/reflect/Field;->get(Ljava/lang/Object;)Ljava/lang/Object;"
        ]

        for caller, callees in self.index["call_graph"].items():
            for callee in callees:
                if callee in methods_to_check:
                    reflective_calls.append((caller, callee))

        if reflective_calls:
            self.writer.startWriter("REFLECTIVE_CALLS", LEVEL_NOTICE, "Use of Reflection Detected",
                                    "The application uses reflection, which can make the code harder to analyze and can be used to hide malicious behavior. Manual review is recommended.",
                                    ["Reflection"], vector_name=self.vector_name,
                                    suggestion="Ensure that reflection is used safely and that it does not introduce any security vulnerabilities.",
                                    confidence=3, risk="Low")
            self.writer.write("Reflective calls found:")
            for caller, callee in reflective_calls:
                self.writer.write(f"    {caller} -> {callee}")

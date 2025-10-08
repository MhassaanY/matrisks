from vector_base import Vector
from constants import *
from taint_analysis.taint_analyzer import TaintAnalyzer
import os

class Vector(Vector):
    description = "Performs taint analysis to detect data leaks."
    tags = ["TAINT_ANALYSIS"]

    def __init__(self, writer, apk, vm, vm_analysis, decompiler, call_graph, native_analyzer, args, config, filtering_engine):
        super().__init__(writer, apk, vm, vm_analysis, decompiler, call_graph, native_analyzer, args, config, filtering_engine)

    def analyze(self) -> None:
        if not self.index:
            return

        taint_analyzer = TaintAnalyzer(self.analysis, self.index)
        sources_and_sinks_path = os.path.join(os.path.dirname(__file__), "..", "taint_analysis", "sources_and_sinks.json")
        taint_analyzer.load_sources_and_sinks(sources_and_sinks_path)
        leaks = taint_analyzer.analyze()

        if leaks:
            self.writer.startWriter("DATA_LEAK", LEVEL_CRITICAL, "Potential Data Leak Detected",
                                    "The application sends sensitive data to a sink. This could be a privacy violation.",
                                    ["Security", "Privacy"], vector_name=self.vector_name,
                                    suggestion="Ensure that sensitive data is not logged or sent to third-party servers.",
                                    confidence=4, risk="High")
            for leak in leaks:
                self.writer.write(f"Leak found in method: {leak['method']}")
                self.writer.write(f"  Source: {leak['source']}")
                self.writer.write(f"  Sink: {leak['sink']}")
                self.writer.write("  Data flow path:")
                for step in leak['path']:
                    self.writer.write(f"    -> {step[0]} (instruction offset: {step[1]})")

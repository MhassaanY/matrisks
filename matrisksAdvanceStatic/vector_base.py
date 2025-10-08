from abc import ABC, abstractmethod

try:
    # Try androguard 4.x imports
    from androguard.core.apk import APK
    from androguard.core.dex import DEX as DalvikVMFormat
    from androguard.core.analysis.analysis import Analysis
except ImportError:
    # Fall back to androguard 3.x imports
    from androguard.core.bytecodes.apk import APK
    from androguard.core.bytecodes.dvm import DalvikVMFormat
    from androguard.core.analysis.analysis import Analysis

import os
import json

from writer import Writer

from engines import FilteringEngine
from constants import ENABLE_EXCLUDE_CLASSES, STR_REGEXP_TYPE_EXCLUDE_CLASSES


class VectorBase(ABC):
    """
    This abstract class is used to define vulnerability vectors for the Matrisks vulnerability scanner.
    """

class Vector:
    def __init__(self, writer, apk, vm, vm_analysis, decompiler, call_graph, native_analyzer, args, config, filtering_engine):
        self.writer = writer
        self.apk = apk
        self.dalvik = vm
        self.vm = vm
        self.analysis = vm_analysis
        self.decompiler = decompiler
        self.call_graph = call_graph
        self.native_analyzer = native_analyzer
        self.args = args
        self.config = config
        self.filtering_engine = filtering_engine
        self.vector_name = self.__class__.__module__
        self.index = self._load_index()

    def _load_index(self):
        index_path = os.path.join(self.writer.staging_dir, "analysis_index.json")
        if os.path.exists(index_path):
            with open(index_path, 'r') as f:
                return json.load(f)
        return None

    def _print_xrefs(self, string_analysis, indention_space_count=0) -> None:
        """
        Prints the xrefs from a StringAnalysis Object to the writer
        """
        for xref_class, xref_method in string_analysis.get_xref_from():
            source_classes_and_functions = (
                    xref_class.name + "->" + xref_method.get_name() + xref_method.get_descriptor())
            self.writer.write("    ->From class: " + source_classes_and_functions)

    @property
    @abstractmethod
    def description(self) -> str:
        """
        Short description of the vulnerability vector.
        :return: str
        """
        pass


    @property
    @abstractmethod
    def tags(self) -> [str]:
        """
        Tags associated with the vulnerability vector (e.g. one or more categories).
        :return: str
        """
        pass

    @abstractmethod
    def analyze(self) -> None:
        """
        Analyze the application for the described vulnerability.
        Results may be passed to the writer.
        :return: None
        """
        pass

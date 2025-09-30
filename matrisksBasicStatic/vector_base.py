from abc import ABC, abstractmethod

from androguard.core.analysis.analysis import Analysis
from androguard.core.apk import APK
from androguard.core.dex import DEX

from writer import Writer

from engines import FilteringEngine
from constants import ENABLE_EXCLUDE_CLASSES, STR_REGEXP_TYPE_EXCLUDE_CLASSES


class VectorBase(ABC):
    """
    This abstract class is used to define vulnerability vectors for the Matrisks vulnerability scanner.
    """

    def __init__(self, writer: Writer, apk: APK, dalvik: DEX, analysis: Analysis, args: any = None, int_min_sdk: int = 1, int_target_sdk: int = 1) -> None:
        """
        Initialize the vector class with the resources needed for analysis.
        :param writer: Output writer.
        :param apk: APK object.
        :param dalvik: Dalvik VM object.
        :param analysis: Analysis object.
        :param args: Optional arguments.
        """
        self.writer = writer
        self.apk = apk
        self.dalvik = dalvik
        self.analysis = analysis
        self.args = args
        self.filtering_engine = FilteringEngine(ENABLE_EXCLUDE_CLASSES, STR_REGEXP_TYPE_EXCLUDE_CLASSES)
        self.int_target_sdk = int_target_sdk
        self.int_min_sdk = int_min_sdk

    def _print_xrefs(self, string_analysis) -> None:
        """
        Prints the xrefs from a StringAnalysis Object to the writer
        """
        for xref_entry in string_analysis.get_xref_from():
            if len(xref_entry) == 3:
                xref_class, xref_method, _ = xref_entry
            else:
                xref_class, xref_method = xref_entry

            if hasattr(xref_method, "get_method"):
                xref_method = xref_method.get_method()

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
    def tags(self) -> list[str]:
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

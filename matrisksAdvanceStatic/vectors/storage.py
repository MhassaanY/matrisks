import staticDVM
from vector_base import Vector
from constants import *

class Vector(Vector):
    def __init__(self, writer, apk, vm, vm_analysis, decompiler, call_graph, native_analyzer, args, config, filtering_engine):
        super().__init__(writer, apk, vm, vm_analysis, decompiler, call_graph, native_analyzer, args, config, filtering_engine)
    description = "Unsafe file deletion checks"
    tags = ["FILE_DELETE"]

    def analyze(self) -> None:
        # File delete alert

        file_delete_method_analysis_list = self.analysis.find_methods("Ljava/io/File;", "delete")
        file_delete_method_analysis_list = staticDVM.get_paths(file_delete_method_analysis_list)

        if file_delete_method_analysis_list:
            self.writer.startWriter("FILE_DELETE", LEVEL_NOTICE, "File Unsafe Delete Checking",
                                    """Everything you delete may be recovered by any user or attacker, especially rooted devices.
    Please make sure do not use "file.delete()" to delete essential files.
    Check this video: https://www.youtube.com/watch?v=tGw1fxUD-uY""", vector_name=self.vector_name)
            self.writer.show_Paths(file_delete_method_analysis_list)
        else:
            self.writer.startWriter("FILE_DELETE", LEVEL_INFO, "File Unsafe Delete Checking",
                                    "Did not detect that you are unsafely deleting files.", vector_name=self.vector_name)

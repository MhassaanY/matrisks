import staticDVM
from vector_base import Vector
from constants import *

class Vector(Vector):
    def __init__(self, writer, apk, vm, vm_analysis, decompiler, call_graph, native_analyzer, args, config, filtering_engine):
        super().__init__(writer, apk, vm, vm_analysis, decompiler, call_graph, native_analyzer, args, config, filtering_engine)
    description = "Checks if sdk allows Google Cloud Messaging (Push Message) service"
    tags = ["MANIFEST_GCM"]

    def analyze(self) -> None:

        if int(self.apk.get_min_sdk_version()) < 8:  # Android 2.2=SDK 8

            output_string = """Your supporting minSdk is %d
        You are now allowing minSdk to less than 8. Please check: http://developer.android.com/about/dashboards/index.html
        Google Cloud Messaging (Push Message) service only allows Android SDK >= 8 (Android 2.2). Pleae check: http://developer.android.com/google/gcm/gcm.html
        You may have the change to use GCM in the future, so please set minSdk to at least 9.""" % int(self.apk.get_min_sdk_version())

            self.writer.startWriter("MANIFEST_GCM", LEVEL_NOTICE, "Google Cloud Messaging Suggestion", output_string, vector_name=self.vector_name)

        else:
            self.writer.startWriter("MANIFEST_GCM", LEVEL_INFO, "Google Cloud Messaging Suggestion", "Nothing to suggest.", vector_name=self.vector_name)

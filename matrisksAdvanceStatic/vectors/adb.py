from vector_base import Vector
from constants import *

class Vector(Vector):
    def __init__(self, writer, apk, vm, vm_analysis, decompiler, call_graph, native_analyzer, args, config, filtering_engine):
        super().__init__(writer, apk, vm, vm_analysis, decompiler, call_graph, native_analyzer, args, config, filtering_engine)
    description = "Checks adb backup"
    tags = ["ALLOW_BACKUP"]

    def analyze(self) -> None:
        # Adb Backup check

        if self.apk.get_attribute_value("application", "allowBackup") in ("true", None):
            self.writer.startWriter("ALLOW_BACKUP", LEVEL_NOTICE, "ADB Backup is Enabled",
                               """ADB Backup is ENABLED for this app (default: ENABLED). An attacker with physical access to an unlocked device can copy sensitive application data via `adb backup`.
    Reference: http://developer.android.com/guide/topics/manifest/application-element.html#allowbackup
    """, vector_name=self.vector_name,
                               suggestion="If the application does not need to be backed up, explicitly set android:allowBackup=\"false\" in the AndroidManifest.xml.",
                               confidence=5, risk="Medium")
        else:
            self.writer.startWriter("ALLOW_BACKUP", LEVEL_INFO, "AndroidManifest Adb Backup Checking",
                               "This app has disabled Adb Backup.", vector_name=self.vector_name)
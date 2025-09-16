import staticDVM
from vector_base import VectorBase
from constants import *


class Vector(VectorBase):
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
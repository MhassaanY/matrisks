from vector_base import Vector
from constants import *

class Vector(Vector):
    description = "Checks for insecure data storage vulnerabilities."
    tags = ["INSECURE_DATA_STORAGE"]

    def __init__(self, writer, apk, vm, vm_analysis, decompiler, call_graph, native_analyzer, args, config, filtering_engine):
        super().__init__(writer, apk, vm, vm_analysis, decompiler, call_graph, native_analyzer, args, config, filtering_engine)

    def analyze(self) -> None:
        if not self.index:
            return
        self.check_insecure_file_permissions()
        self.check_external_storage()

    def check_insecure_file_permissions(self):
        """Finds files and databases created with world-readable or world-writable permissions."""
        vulnerable_calls = []
        methods_to_check = [
            "Landroid/content/ContextWrapper;->openFileOutput(Ljava/lang/String; I)Ljava/io/FileOutputStream;",
            "Landroid/content/ContextWrapper;->getSharedPreferences(Ljava/lang/String; I)Landroid/content/SharedPreferences;",
            "Landroid/content/ContextWrapper;->getDir(Ljava/lang/String; I)Ljava/io/File;",
            "Landroid/database/sqlite/SQLiteDatabase;->openOrCreateDatabase(Ljava/lang/String; Landroid/database/sqlite/SQLiteDatabase$CursorFactory; I)Landroid/database/sqlite/SQLiteDatabase;"
        ]

        for caller, callees in self.index["call_graph"].items():
            for callee in callees:
                if callee in methods_to_check:
                    vulnerable_calls.append((caller, callee))

        if vulnerable_calls:
            self.writer.startWriter("INSECURE_FILE_PERMISSIONS", LEVEL_CRITICAL, "Insecure File Permissions",
                                    "The application creates files, directories, or databases with world-readable or world-writable permissions. This can allow other applications on the device to access or modify their data.",
                                    ["Storage"], vector_name=self.vector_name,
                                    suggestion="Use MODE_PRIVATE for all files, shared preferences, and databases that should only be accessible to your application.",
                                    confidence=5, risk="High")
            self.writer.write("Insecure file permissions set in:")
            for caller, callee in vulnerable_calls:
                self.writer.write(f"    {caller} -> {callee}")

    def check_external_storage(self):
        """Finds usage of external storage, which is globally accessible."""
        vulnerable_calls = []
        methods_to_check = [
            "Landroid/os/Environment;->getExternalStorageDirectory()Ljava/io/File;",
            "Landroid/os/Environment;->getExternalStoragePublicDirectory(Ljava/lang/String;)Ljava/io/File;"
        ]

        for caller, callees in self.index["call_graph"].items():
            for callee in callees:
                if callee in methods_to_check:
                    vulnerable_calls.append((caller, callee))

        if vulnerable_calls:
            self.writer.startWriter("EXTERNAL_STORAGE_USAGE", LEVEL_WARNING, "External Storage Usage",
                                    "The application reads or writes to external storage. Data stored on external storage is accessible to any application with the READ/WRITE_EXTERNAL_STORAGE permission and can be read by a user with access to the device.",
                                    ["Storage"], vector_name=self.vector_name,
                                    suggestion="Do not store sensitive data on external storage. Use the application's private internal storage instead.",
                                    confidence=5, risk="Medium")
            self.writer.write("External storage used in:")
            for caller, callee in vulnerable_calls:
                self.writer.write(f"    {caller} -> {callee}")
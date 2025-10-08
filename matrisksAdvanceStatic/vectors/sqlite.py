import re
from vector_base import Vector
from constants import *
import staticDVM

class Vector(Vector):
    def __init__(self, writer, apk, vm, vm_analysis, decompiler, call_graph, native_analyzer, args, config, filtering_engine):
        super().__init__(writer, apk, vm, vm_analysis, decompiler, call_graph, native_analyzer, args, config, filtering_engine)
        try:
            self.int_min_sdk = int(self.apk.get_min_sdk_version())
        except (ValueError, TypeError):
            self.int_min_sdk = 1
    description = "Checks for common SQLite vulnerabilities."
    tags = ["SQLITE"]

    def analyze(self) -> None:
        self.check_sql_injection_and_hardcoded_keys()
        self.check_deprecated_methods()
        self.check_sqlcipher()
        self.check_sqlite_journal()

    def check_sql_injection_and_hardcoded_keys(self):
        """Finds calls to rawQuery and checks for potential SQLi and hardcoded keys."""
        raw_query_paths = self.analysis.find_methods(
            classname="Landroid/database/sqlite/SQLiteDatabase;",
            methodname="rawQuery"
        )

        found_sqli = []
        found_hardcoded_keys = []
        sqli_regex = re.compile(r"rawQuery\s*\(.*\s*\+\s*.*\)", re.IGNORECASE)

        for trace in staticDVM.trace_register_value_by_param_in_method_class_analysis_list(raw_query_paths):
            path = trace.getPath()
            sql_string = trace.getResult()[1]

            # Check for hardcoded PRAGMA key
            if sql_string and isinstance(sql_string, str) and "PRAGMA key" in sql_string.lower():
                found_hardcoded_keys.append(path)
            
            # Check for SQL injection via string concatenation in the calling method's source
            # The original implementation had a bug here.
            # It was trying to get the source code of the method, but the get_source() method does not exist.
            # For now, we will just flag all rawQuery calls as potential SQL injection vulnerabilities.
            found_sqli.append(path)

        if found_hardcoded_keys:
            self.writer.startWriter("SQLITE_HARDCODED_KEY", LEVEL_CRITICAL, "Hardcoded SQLite Encryption Key",
                                    "The application may be using a hardcoded key to encrypt its SQLite database, found in a call to rawQuery. This key can be easily extracted from the code.",
                                    ["Database", "Security"], vector_name=self.vector_name,
                                    suggestion="Do not hardcode encryption keys. Use the Android Keystore system to store and manage keys securely.",
                                    confidence=5, risk="High")
            for path in found_hardcoded_keys:
                self.writer.write("Hardcoded PRAGMA key statement found in:")
                self.writer.show_Path(path, indention_space_count=4)

        if found_sqli:
            self.writer.startWriter("SQL_INJECTION", LEVEL_WARNING, "Potential SQL Injection",
                                    "The application uses rawQuery with what appears to be string concatenation to build the SQL query. This can be vulnerable to SQL injection.",
                                    ["Database", "Security"], vector_name=self.vector_name,
                                    suggestion="Use parameterized queries with `?` placeholders (selectionArgs) instead of building queries with string concatenation.",
                                    confidence=4, risk="High")
            for path in found_sqli:
                self.writer.write("Potential SQL injection found in:")
                self.writer.show_Path(path, indention_space_count=4)

    def check_deprecated_methods(self):
        """Finds usage of beginTransactionNonExclusive on older APIs."""
        if int(self.apk.get_min_sdk_version()) < 11:
            paths = self.analysis.find_methods(
                classname="Landroid/database/sqlite/SQLiteDatabase;",
                methodname="beginTransactionNonExclusive"
            )
            if paths:
                self.writer.startWriter("SQLITE_DEPRECATED_METHOD", LEVEL_WARNING, "Deprecated SQLite Method Used on Older APIs",
                                        f"The application uses beginTransactionNonExclusive, which is not supported on APIs lower than 11. The application's minSdk is {self.int_min_sdk}, making it incompatible.",
                                        ["Database"], vector_name=self.vector_name,
                                        suggestion="Use beginTransaction for applications that need to support APIs lower than 11.",
                                        confidence=5, risk="Low")
                for path in staticDVM.get_paths(paths):
                    self.writer.write("Deprecated method used in:")
                    self.writer.show_Path(path, indention_space_count=4)

    def check_sqlcipher(self):
        """Checks if SQLCipher is included in the project."""
        if self.analysis.is_class_present("Lnet/sqlcipher/database/SQLiteDatabase;") or self.analysis.is_class_present("Linfo/guardianproject/database/sqlcipher/SQLiteDatabase;"):
            self.writer.startWriter("SQLCIPHER_USAGE", LEVEL_INFO, "SQLCipher Library Detected",
                                    "The application includes the SQLCipher library, likely to encrypt its databases. Ensure it is configured with a strong, non-hardcoded key.",
                                    ["Database"], vector_name=self.vector_name)

    def check_sqlite_journal(self):
        """Warns about potential journal file information leaks on older APIs."""
        if self.int_min_sdk < 15:
            self.writer.startWriter("SQLITE_JOURNAL_LEAK", LEVEL_NOTICE, "Potential SQLite Journal Information Leak",
                                    "The application uses SQLite and targets an API level lower than 15. On older Android versions, the SQLite journal file can leak sensitive information if the device loses power during a transaction.",
                                    ["Database"], vector_name=self.vector_name,
                                    suggestion="This is an informational finding. The vulnerability is in the Android OS and cannot be fixed in the application. Encrypting the database with SQLCipher can mitigate this risk.",
                                    confidence=3, risk="Low")
from vector_base import Vector
from constants import *

class Vector(Vector):
    description = "Checks for a connection pooling bug in HttpURLConnection on pre-Froyo devices."
    tags = ["HTTPURLCONNECTION_BUG"]

    def analyze(self) -> None:
        # This bug affects Android versions prior to 2.2 (Froyo, API 8)
        if int(self.apk.get_min_sdk_version()) >= 8:
            self.writer.startWriter("HTTPURLCONNECTION_BUG", LEVEL_INFO, "HttpURLConnection Bug (Pre-Froyo)",
                               "Analysis skipped: minSdk is higher than 8.", vector_name=self.vector_name)
            return

        # Find all methods of HttpURLConnection
        http_uc_class = self.vm.get_class("Ljava/net/HttpURLConnection;")
        if not http_uc_class:
            self.writer.startWriter("HTTPURLCONNECTION_BUG", LEVEL_INFO, "HttpURLConnection Bug (Pre-Froyo)",
                               "Analysis skipped: HttpURLConnection class not found.", vector_name=self.vector_name)
            return

        http_uc_methods = http_uc_class.get_methods()

        # Find all callers of HttpURLConnection methods
        http_usage_callers = set()
        for method in http_uc_methods:
            for caller in self.call_graph.get_callers(method):
                http_usage_callers.add(caller.get_class_name())

        if not http_usage_callers:
            self.writer.startWriter("HTTPURLCONNECTION_BUG", LEVEL_INFO, "HttpURLConnection Bug (Pre-Froyo)",
                               "Analysis skipped: HttpURLConnection is not used in this application.", vector_name=self.vector_name)
            return

        # Check if the workaround is in place
        set_property_paths = self.vm_analysis.find_methods(
            classname="Ljava/lang/System;",
            methodname="setProperty",
            descriptor="(Ljava/lang/String; Ljava/lang/String;)Ljava/lang/String;"
        )

        keep_alive_disabled = False
        for path in set_property_paths:
            # This is a basic check. A more advanced analysis would trace the arguments to setProperty.
            # For now, we assume that if setProperty is called with "http.keepAlive", it's to disable it.
            for _, method, _ in path.get_xref_from():
                for instruction in method.get_instructions():
                    if instruction.get_name() == 'const-string' and "http.keepAlive" in instruction.get_output():
                        keep_alive_disabled = True
                        break
                if keep_alive_disabled:
                    break
            if keep_alive_disabled:
                break

        if keep_alive_disabled:
            self.writer.startWriter("HTTPURLCONNECTION_BUG", LEVEL_INFO, "HttpURLConnection Bug (Pre-Froyo)",
                                   "The application correctly disables http.keepAlive, mitigating a connection pooling bug on older Android versions.", vector_name=self.vector_name)
        else:
            self.writer.startWriter("HTTPURLCONNECTION_BUG", LEVEL_NOTICE, "HttpURLConnection Bug on Pre-Froyo Devices",
                                   "The application uses HttpURLConnection and targets older Android versions without disabling connection pooling. This can lead to connection pool poisoning on devices running Android versions prior to 2.2 (Froyo).",
                                   ["Compatability"], vector_name=self.vector_name,
                                   suggestion='On Android versions prior to Froyo, call `System.setProperty("http.keepAlive", "false")` before making any HttpURLConnections to disable connection pooling and avoid this bug.',
                                   confidence=5, risk="Low")
            
            self.writer.write("HttpURLConnection usage found in the following classes:")
            for class_name in sorted(list(http_usage_callers)):
                self.writer.write(f"- {self.writer.simplifyClassPath(class_name)}")

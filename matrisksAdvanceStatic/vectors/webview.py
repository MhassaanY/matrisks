from vector_base import Vector
from constants import *
import staticDVM

class Vector(Vector):
    def __init__(self, writer, apk, vm, vm_analysis, decompiler, call_graph, native_analyzer, args, config, filtering_engine):
        super().__init__(writer, apk, vm, vm_analysis, decompiler, call_graph, native_analyzer, args, config, filtering_engine)
    description = "Checks for common WebView vulnerabilities."
    tags = ["WEBVIEW"]

    def analyze(self) -> None:
        self.check_javascript_interface()
        self.check_ssl_error_handler()
        self.check_javascript_enabled()
        self.check_file_access()

    def check_javascript_interface(self):
        """Finds usage of addJavascriptInterface, which is dangerous on older Android versions."""
        paths = self.analysis.find_methods(
            classname="Landroid/webkit/WebView;",
            methodname="addJavascriptInterface"
        )
        if paths:
            self.writer.startWriter("WEBVIEW_JS_INTERFACE", LEVEL_CRITICAL, "WebView addJavascriptInterface Enabled",
                                    "The application uses addJavascriptInterface. On Android versions before 4.2 (Jelly Bean), this can allow remote code execution if the WebView loads untrusted content.",
                                    ["WebView", "Remote Code Execution"], vector_name=self.vector_name,
                                    suggestion="Review all uses of addJavascriptInterface. If the app runs on Android < 4.2, do not load untrusted web content. For newer versions, ensure exposed Java objects do not contain sensitive methods.",
                                    confidence=5, risk="Critical")
            for path in staticDVM.get_paths(paths):
                self.writer.write("addJavascriptInterface used in:")
                self.writer.show_Path(path, indention_space_count=4)

    def check_ssl_error_handler(self):
        """Finds onReceivedSslError handlers that blindly call handler.proceed()."""
        vulnerable_methods = []
        # Find all classes that extend WebViewClient
        webview_clients = []
        for cls in self.analysis.get_classes():
            if not cls.is_external() and cls.get_vm_class().get_superclassname() == 'Landroid/webkit/WebViewClient;':
                webview_clients.append(cls)

        for client_class in webview_clients:
            for method in client_class.get_methods():
                if method.get_name() == 'onReceivedSslError' and method.get_descriptor() == '(Landroid/webkit/WebView; Landroid/webkit/SslErrorHandler; Landroid/net/http/SslError;)V':
                    # Look for a call to SslErrorHandler.proceed()
                    for ins in method.get_instructions():
                        if ins.get_name() == 'invoke-virtual' and ins.get_operands()[-1][1].get_class_name() == 'Landroid/webkit/SslErrorHandler;' and ins.get_operands()[-1][1].get_name() == 'proceed':
                            vulnerable_methods.append(method)
                            break
        
        if vulnerable_methods:
            self.writer.startWriter("WEBVIEW_SSL_ERROR_BYPASS", LEVEL_CRITICAL, "Insecure WebView SSL Error Handler",
                                    "The application's WebViewClient ignores SSL errors by calling handler.proceed() in onReceivedSslError. This makes the application vulnerable to Man-in-the-Middle (MITM) attacks.",
                                    ["WebView", "SSL_Security"], vector_name=self.vector_name,
                                    suggestion="Do not call handler.proceed() in onReceivedSslError. Let the WebView cancel the request to ensure secure communication.",
                                    confidence=5, risk="Critical")
            for method in vulnerable_methods:
                self.writer.write(f"Insecure SSL error handler found in: {self.writer.simplifyClassPath(method.get_class_name())}->{method.get_name()}")

    def check_javascript_enabled(self):
        """Checks if JavaScript is enabled in a WebView."""
        paths = self.analysis.find_methods(
            classname="Landroid/webkit/WebSettings;",
            methodname="setJavaScriptEnabled",
            descriptor="(Z)V"
        )
        
        vulnerable_paths = []
        for trace in staticDVM.trace_register_value_by_param_in_method_class_analysis_list(paths):
            # Parameter 1 is the boolean value. In Dalvik, true is 1.
            if trace.getResult()[1] == 1:
                vulnerable_paths.append(trace.getPath())

        if vulnerable_paths:
            self.writer.startWriter("WEBVIEW_JS_ENABLED", LEVEL_WARNING, "WebView JavaScript Enabled",
                                    "The application enables JavaScript in a WebView. If the WebView loads untrusted content, this could expose the application to Cross-Site Scripting (XSS) attacks.",
                                    ["WebView"], vector_name=self.vector_name,
                                    suggestion="Only enable JavaScript if the WebView loads trusted content. If untrusted content is loaded, ensure it is properly sanitized to prevent XSS.",
                                    confidence=4, risk="Medium")
            for path in vulnerable_paths:
                self.writer.write("JavaScript enabled in:")
                self.writer.show_Path(path, indention_space_count=4)

    def check_file_access(self):
        """Checks if file access is enabled in a WebView."""
        paths = self.analysis.find_methods(
            classname="Landroid/webkit/WebSettings;",
            methodname="setAllowFileAccess",
            descriptor="(Z)V"
        )

        vulnerable_paths = []
        for trace in staticDVM.trace_register_value_by_param_in_method_class_analysis_list(paths):
            if trace.getResult()[1] == 1:
                vulnerable_paths.append(trace.getPath())

        if vulnerable_paths:
            self.writer.startWriter("WEBVIEW_FILE_ACCESS_ENABLED", LEVEL_WARNING, "WebView File Access Enabled",
                                    "The application enables file access in a WebView. If the WebView loads malicious content, it could be used to access local files on the device.",
                                    ["WebView"], vector_name=self.vector_name,
                                    suggestion="Disable file access in WebViews that load untrusted content by calling setAllowFileAccess(false).",
                                    confidence=4, risk="Medium")
            for path in vulnerable_paths:
                self.writer.write("File access enabled in:")
                self.writer.show_Path(path, indention_space_count=4)
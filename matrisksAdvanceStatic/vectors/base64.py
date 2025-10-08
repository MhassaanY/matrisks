import base64
import re
import staticDVM
from vector_base import Vector
from constants import *

class Vector(Vector):
    def __init__(self, writer, apk, vm, vm_analysis, decompiler, call_graph, native_analyzer, args, config, filtering_engine):
        super().__init__(writer, apk, vm, vm_analysis, decompiler, call_graph, native_analyzer, args, config, filtering_engine)
    description = "Checks for Base64 encoded strings and insecure HTTP URLs."
    tags = ["BASE64_DECODING", "INSECURE_HTTP_URL"]

    def analyze(self) -> None:
        self.check_base64_decoding()
        self.check_for_http_urls()

    def check_base64_decoding(self) -> None:
        """Finds hardcoded strings that are passed to Base64.decode()."""
        found_strings = []
        # Find all variants of Base64.decode
        decode_paths = self.analysis.find_methods(
            classname="Landroid/util/Base64;", 
            methodname="decode"
        )

        for trace in staticDVM.trace_register_value_by_param_in_method_class_analysis_list(decode_paths):
            # The first parameter (index 1) is the one to be decoded (either String or byte[]).
            # We are interested when it's a hardcoded string.
            encoded_string = trace.getResult()[1]
            if encoded_string and isinstance(encoded_string, str):
                try:
                    decoded_bytes = base64.b64decode(encoded_string)
                    # Try to decode as UTF-8, but don't fail if it's binary data
                    decoded_string = decoded_bytes.decode('utf-8', errors='replace')
                    found_strings.append((encoded_string, decoded_string, trace.getPath()))
                except (ValueError, TypeError):
                    # Not a valid Base64 string, ignore.
                    continue

        if found_strings:
            self.writer.startWriter("BASE64_DECODING", LEVEL_NOTICE, "Hardcoded Base64 Encoded Strings Found",
                                    "The application decodes hardcoded Base64 strings. This is often used to obscure data, but it is not a form of encryption. Review the decoded content to ensure no sensitive data is exposed.",
                                    ["Cryptography"], vector_name=self.vector_name,
                                    suggestion="Do not use Base64 to obscure secrets. If the data is sensitive, encrypt it using a strong algorithm like AES-GCM and store keys securely.",
                                    confidence=4, risk="Medium")
            for original, decoded, path in found_strings:
                self.writer.write(f'Decoded string: "{decoded[:200]}' + ("..." if len(decoded) > 200 else "") + '"')
                self.writer.write(f'  - Original encoded string: "{original}"')
                self.writer.write("  - Location:")
                self.writer.show_Path(path, indention_space_count=4)

    def check_for_http_urls(self) -> None:
        """Finds hardcoded http:// URLs in the code."""
        strings_analysis = self.analysis.get_strings_analysis()
        regex_excluded_class_names = re.compile(STR_REGEXP_TYPE_EXCLUDE_CLASSES)
        
        exception_url_string = {
            "http://example.com", "http://example.com/",
            "http://www.example.com", "http://www.example.com/",
            "http://www.google-analytics.com/collect", "http://www.google-analytics.com",
            "http://hostname/?", "http://hostname/",
        }
        
        url_prefixes_to_ignore = (
            "http://schemas.android.com/", "http://www.w3.org/",
            "http://apache.org/", "http://xml.org/",
            "http://localhost/", "http://java.sun.com/"
        )
        
        url_suffixes_to_ignore = (
            "/namespace", "-dtd", ".dtd", "-handler", "-instance"
        )

        filtered_urls = []
        for url, s_analysis in strings_analysis.items():
            if not url.startswith("http://"):
                continue

            if url in exception_url_string or url.startswith(url_prefixes_to_ignore) or url.endswith(url_suffixes_to_ignore):
                continue

            # only append url if it is not in the exclusion list
            if not any(regex_excluded_class_names.match(xref_class.name) for xref_class, _ in s_analysis.get_xref_from()):
                filtered_urls.append((url, s_analysis))

        if filtered_urls:
            self.writer.startWriter("INSECURE_HTTP_URL", LEVEL_CRITICAL, "Insecure HTTP URLs Found",
                                    "The application connects to URLs using unencrypted HTTP. This can expose data to network eavesdropping.",
                                    ["SSL_Security"], vector_name=self.vector_name,
                                    suggestion="All network communication should use HTTPS to protect data in transit.",
                                    confidence=5, risk="High")

            for url, s_analysis in filtered_urls:
                self.writer.write(url)
                self._print_xrefs(s_analysis, indention_space_count=2)
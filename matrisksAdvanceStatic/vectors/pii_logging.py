from vector_base import VectorBase
from constants import *
import staticDVM
import re

class Vector(VectorBase):
    description = "Checks for the insecure logging of Personally Identifiable Information (PII)."
    tags = ["PII_LOGGING"]

    PII_PATTERNS = {
        "Email Address": re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'),
        "Phone Number": re.compile(r'(\(\d{3}\)|\d{3})[-.\s]?\d{3}[-.\s]?\d{4}'),
        "Credit Card": re.compile(r'\b(?:\d[ -]*?){13,16}\b'),
        # Add more sensitive keywords that might be logged with user data
        "Password": re.compile(r'(password|passwd|pwd)', re.IGNORECASE),
        "Token": re.compile(r'(token|auth_token|access_token)', re.IGNORECASE),
    }

    def analyze(self) -> None:
        found_pii_logs = set()

        # Find all calls to android.util.Log methods (d, e, i, v, w)
        log_methods = []
        for method_name in ['d', 'e', 'i', 'v', 'w']:
            log_methods.extend(self.analysis.find_methods(
                "Landroid/util/Log;", method_name, "(Ljava/lang/String; Ljava/lang/String;)I"
            ))
            log_methods.extend(self.analysis.find_methods(
                "Landroid/util/Log;", method_name, "(Ljava/lang/String; Ljava/lang/String; Ljava/lang/Throwable;)I"
            ))

        for i in staticDVM.trace_register_value_by_param_in_method_class_analysis_list(log_methods):
            # The message is the second argument (index 2)
            log_message = i.getResult()[2]
            if log_message and isinstance(log_message, str):
                for pii_type, pattern in self.PII_PATTERNS.items():
                    if pattern.search(log_message):
                        finding = f"Potential leak of '{pii_type}' found in logs."
                        found_pii_logs.add(finding)

        if found_pii_logs:
            self.writer.startWriter("PII_LEAK_IN_LOGS", LEVEL_CRITICAL, "Potential PII Leak in Application Logs",
                                    "The application appears to log sensitive user data (PII). Logs can be accessed by other applications on the device, leading to information disclosure.",
                                    ["Security", "PII"], vector_name=self.vector_name,
                                    suggestion="Remove any logging of sensitive user information. Ensure that only non-sensitive, debug-related information is logged.",
                                    confidence=4, risk="High")
            
            for finding in sorted(list(found_pii_logs)):
                self.writer.write(finding)

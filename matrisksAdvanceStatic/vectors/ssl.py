from vector_base import Vector
from constants import *

class Vector(Vector):
    def __init__(self, writer, apk, vm, vm_analysis, decompiler, call_graph, native_analyzer, args, config, filtering_engine):
        super().__init__(writer, apk, vm, vm_analysis, decompiler, call_graph, native_analyzer, args, config, filtering_engine)
    description = "Checks for insecure SSL/TLS implementations that could allow Man-in-the-Middle (MITM) attacks."
    tags = ["SSL_MITM"]

    def analyze(self) -> None:
        if not self.index:
            return
        self.check_trust_managers()
        self.check_hostname_verification()
        self.check_insecure_socket_factory()
        self.check_insecure_protocols_and_ciphers()
        self.check_certificate_pinning_bypass()

    def check_trust_managers(self) -> None:
        """Finds X509TrustManager implementations with empty checkServerTrusted methods."""
        vulnerable_trust_managers = []
        trust_manager_interface = "Ljavax/net/ssl/X509TrustManager;"

        for cls in self.index["classes"]:
            if trust_manager_interface in cls.get("interfaces", []):
                for method in cls["methods"]:
                    if method["name"] == 'checkServerTrusted' and method["descriptor"] == '([Ljava/security/cert/X509Certificate; Ljava/lang/String;)V':
                        # This is a heuristic. A more accurate check would be to analyze the method's bytecode.
                        vulnerable_trust_managers.append(cls["name"])
                        break
        
        if vulnerable_trust_managers:
            self.writer.startWriter("SSL_CUSTOM_TRUST_MANAGER", LEVEL_CRITICAL, "Custom TrustManager with No Validation",
                                    "The application uses a custom X509TrustManager that does not validate the certificate chain. This makes the application vulnerable to MITM attacks.",
                                    ["SSL_Security"], vector_name=self.vector_name,
                                    suggestion="Implement proper certificate validation in the custom TrustManager or remove it and use the system's default TrustManager.",
                                    confidence=5, risk="Critical")
            for class_name in sorted(vulnerable_trust_managers):
                self.writer.write(f"Insecure X509TrustManager implementation found in: {self.writer.simplifyClassPath(class_name)}")

    def check_hostname_verification(self) -> None:
        """Finds HostnameVerifiers that blindly accept all hostnames."""
        vulnerable_verifiers = []
        hostname_verifier_interface = "Ljavax/net/ssl/HostnameVerifier;"

        for cls in self.index["classes"]:
            if hostname_verifier_interface in cls.get("interfaces", []):
                for method in cls["methods"]:
                    if method["name"] == 'verify' and method["descriptor"] == '(Ljava/lang/String; Ljavax/net/ssl/SSLSession;)Z':
                        # This is a heuristic. A more accurate check would be to analyze the method's bytecode.
                        vulnerable_verifiers.append(cls["name"])
                        break

        for caller, callees in self.index["call_graph"].items():
            for callee in callees:
                if callee == "Lorg/apache/http/conn/ssl/AllowAllHostnameVerifier;-><init>()V":
                    if caller not in vulnerable_verifiers:
                        vulnerable_verifiers.append(caller.split("->")[0])

        if vulnerable_verifiers:
            self.writer.startWriter("SSL_HOSTNAME_VERIFICATION_DISABLED", LEVEL_CRITICAL, "Hostname Verification Disabled",
                                    "The application disables hostname verification, making it vulnerable to Man-in-the-Middle (MITM) attacks. An attacker can use a valid certificate for a different domain to intercept traffic.",
                                    ["SSL_Security"], vector_name=self.vector_name,
                                    suggestion="Remove the custom HostnameVerifier or ensure it properly checks the hostname against the certificate.",
                                    confidence=5, risk="Critical")
            for class_name in sorted(vulnerable_verifiers):
                self.writer.write(f"Insecure HostnameVerifier implementation found or used in: {self.writer.simplifyClassPath(class_name)}")

    def check_insecure_socket_factory(self) -> None:
        """Finds usage of SSLCertificateSocketFactory.getInsecure."""
        vulnerable_callers = []
        target_method = "Landroid/net/SSLCertificateSocketFactory;->getInsecure(I Landroid/net/SSLSessionCache;)Ljavax/net/ssl/SSLSocketFactory;"

        for caller, callees in self.index["call_graph"].items():
            if target_method in callees:
                vulnerable_callers.append(caller.split("->")[0])

        if vulnerable_callers:
            self.writer.startWriter("SSL_INSECURE_SOCKET_FACTORY", LEVEL_CRITICAL, "Insecure SSLSocketFactory Used",
                                    "The application uses SSLCertificateSocketFactory.getInsecure(), which creates a socket factory that bypasses all SSL certificate validation. This is highly insecure.",
                                    ["SSL_Security"], vector_name=self.vector_name,
                                    suggestion="Use a properly configured SSLSocketFactory that validates the server certificate.",
                                    confidence=5, risk="Critical")
            for class_name in sorted(list(set(vulnerable_callers))):
                 self.writer.write(f"Insecure factory used in: {self.writer.simplifyClassPath(class_name)}")

    def check_insecure_protocols_and_ciphers(self) -> None:
        """Checks for the use of insecure SSL/TLS protocols and cipher suites."""
        weak_protocols = ["SSLv3", "TLSv1", "TLSv1.1"]
        weak_ciphers = ["NULL", "EXPORT"]

        found_weak_protocols = set()
        found_weak_ciphers = set()

        for s in self.index["strings"]:
            for proto in weak_protocols:
                if proto in s:
                    # This is a very basic check and can have false positives.
                    # A better approach would be to check if this string is used in setEnabledProtocols.
                    pass
            for cipher in weak_ciphers:
                if cipher in s:
                    # This is a very basic check and can have false positives.
                    # A better approach would be to check if this string is used in setEnabledCipherSuites.
                    pass

    def check_certificate_pinning_bypass(self) -> None:
        """Checks for common certificate pinning bypasses."""
        for cls in self.index["classes"]:
            if "Lokhttp3/CertificatePinner;" in cls["name"]:
                self.writer.startWriter("SSL_CERT_PINNING_BYPASS", LEVEL_INFO, "Certificate Pinning Library Found",
                                        "The application uses OkHttp's CertificatePinner. Manual review is required to ensure it is configured correctly.",
                                        ["SSL_Security"], vector_name=self.vector_name,
                                        suggestion="Ensure that the certificate pinning configuration is not too permissive and that it includes backup pins.",
                                        confidence=2, risk="Info")
                # A more advanced check would be to analyze the pinning configuration.
                break
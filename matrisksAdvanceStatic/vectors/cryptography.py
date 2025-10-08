from vector_base import Vector
from constants import *
import staticDVM

class Vector(Vector):
    def __init__(self, writer, apk, vm, vm_analysis, decompiler, call_graph, native_analyzer, args, config, filtering_engine):
        super().__init__(writer, apk, vm, vm_analysis, decompiler, call_graph, native_analyzer, args, config, filtering_engine)
    description = "Checks for the use of weak or broken cryptographic algorithms."
    tags = ["WEAK_CRYPTO"]

    def analyze(self) -> None:
        found_weak_algos = []

        # 1. Check for weak symmetric ciphers (DES, RC4, ECB mode)
        cipher_paths = self.analysis.find_methods(
            classname="Ljavax/crypto/Cipher;", 
            methodname="getInstance", 
            descriptor="(Ljava/lang/String;)Ljavax/crypto/Cipher;"
        )
        for trace in staticDVM.trace_register_value_by_param_in_method_class_analysis_list(cipher_paths):
            algo = trace.getResult()[1]
            if algo and isinstance(algo, str):
                algo_upper = algo.upper()
                path = trace.getPath()
                if "DES" in algo_upper:
                    found_weak_algos.append((
                        "Weak Encryption Algorithm: DES",
                        f"The application uses the DES algorithm, which is outdated and insecure. Use AES-GCM instead.",
                        path
                    ))
                if "RC4" in algo_upper:
                    found_weak_algos.append((
                        "Weak Encryption Algorithm: RC4",
                        f"The application uses the RC4 stream cipher, which has known vulnerabilities. Use AES-GCM instead.",
                        path
                    ))
                if "/ECB/" in algo_upper:
                    found_weak_algos.append((
                        "Insecure Encryption Mode: ECB",
                        f"The application uses ECB mode, which does not provide strong confidentiality. Use a more secure mode like GCM or CBC with a random IV.",
                        path
                    ))

        # 2. Check for weak hashing algorithms (MD5, SHA-1)
        digest_paths = self.analysis.find_methods(
            classname="Ljava/security/MessageDigest;",
            methodname="getInstance",
            descriptor="(Ljava/lang/String;)Ljava/security/MessageDigest;"
        )
        for trace in staticDVM.trace_register_value_by_param_in_method_class_analysis_list(digest_paths):
            algo = trace.getResult()[1]
            if algo and isinstance(algo, str):
                algo_upper = algo.upper()
                path = trace.getPath()
                if "MD5" == algo_upper:
                    found_weak_algos.append((
                        "Weak Hashing Algorithm: MD5",
                        f"The application uses MD5, which is vulnerable to collisions and should not be used for security purposes. Use SHA-256 or a stronger hash function.",
                        path
                    ))
                if "SHA1" == algo_upper or "SHA-1" == algo_upper:
                     found_weak_algos.append((
                        "Weak Hashing Algorithm: SHA-1",
                        f"The application uses SHA-1, which is no longer considered secure against well-funded attackers. Use SHA-256 or a stronger hash function.",
                        path
                    ))

        if found_weak_algos:
            self.writer.startWriter("WEAK_CRYPTO_USAGE", LEVEL_CRITICAL, "Use of Weak Cryptographic Algorithms",
                                    "The application uses outdated or insecure cryptographic algorithms. These should be replaced with modern, secure alternatives (e.g., AES-GCM, SHA-256).",
                                    ["Security", "Cryptography"], vector_name=self.vector_name,
                                    suggestion="Replace weak algorithms like DES, RC4, MD5, and SHA1 with strong, modern alternatives such as AES-GCM for encryption and SHA-256/SHA-3 for hashing.",
                                    confidence=5, risk="High")
            
            for title, finding, path in sorted(found_weak_algos):
                self.writer.write(f"- {title}")
                self.writer.write(f"  Details: {finding}")
                self.writer.write(f"  Location:")
                self.writer.show_Path(path, indention_space_count=4)

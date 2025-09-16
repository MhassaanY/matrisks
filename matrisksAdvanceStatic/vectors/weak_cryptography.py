from vector_base import VectorBase
from constants import *
import staticDVM

class Vector(VectorBase):
    description = "Checks for the use of weak or broken cryptographic algorithms."
    tags = ["WEAK_CRYPTO"]

    WEAK_ALGORITHMS = {
        # Symmetric Ciphers (insecure modes or weak algorithms)
        "DES": "Used a weak encryption algorithm: DES.",
        "ECB": "Used a weak encryption mode: ECB. It does not provide serious message confidentiality.",
        "RC4": "Used a weak encryption algorithm: RC4.",
        
        # Hash Functions
        "MD5": "Used a weak hashing algorithm: MD5. It is vulnerable to collisions.",
        "SHA1": "Used a weak hashing algorithm: SHA-1. It is no longer considered secure against well-funded attackers."
    }

    def analyze(self) -> None:
        found_weak_algos = set()

        # Find calls to Cipher.getInstance and trace the algorithm string
        cipher_methods = self.analysis.find_methods(
            "Ljavax/crypto/Cipher;", "getInstance", "(Ljava/lang/String;)Ljavax/crypto/Cipher;"
        )

        for i in staticDVM.trace_register_value_by_param_in_method_class_analysis_list(cipher_methods):
            if i.getResult()[1] and isinstance(i.getResult()[1], str):
                algo_string = i.getResult()[1].upper()
                for weak_algo, message in self.WEAK_ALGORITHMS.items():
                    if weak_algo in algo_string:
                        found_weak_algos.add(message)
        
        # Also check for common hash types by name
        hash_classes = ["Ljava/security/MessageDigest;", "Lorg/apache/commons/codec/digest/DigestUtils;"]
        for h_class in hash_classes:
            hash_methods = self.analysis.find_methods(h_class, "getInstance", "(Ljava/lang/String;)Ljava/security/MessageDigest;")
            for i in staticDVM.trace_register_value_by_param_in_method_class_analysis_list(hash_methods):
                 if i.getResult()[1] and isinstance(i.getResult()[1], str):
                    algo_string = i.getResult()[1].upper()
                    if "MD5" in algo_string:
                        found_weak_algos.add(self.WEAK_ALGORITHMS["MD5"])
                    if "SHA1" in algo_string or "SHA-1" in algo_string:
                        found_weak_algos.add(self.WEAK_ALGORITHMS["SHA1"])


        if found_weak_algos:
            self.writer.startWriter("WEAK_CRYPTO_USAGE", LEVEL_WARNING, "Use of Weak Cryptographic Algorithms",
                                    "The application appears to use weak or insecure cryptographic algorithms. These should be replaced with modern, secure alternatives (e.g., AES-GCM, SHA-256).",
                                    ["Security", "Cryptography"], vector_name=self.vector_name,
                                    suggestion="Replace weak algorithms like DES, RC4, MD5, and SHA1 with strong, modern alternatives such as AES-GCM for encryption and SHA-256/SHA-3 for hashing.",
                                    confidence=5, risk="High")
            
            for finding in sorted(list(found_weak_algos)):
                self.writer.write(finding)

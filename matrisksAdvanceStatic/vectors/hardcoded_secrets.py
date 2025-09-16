from vector_base import VectorBase
from constants import *
import re
import math
from collections import Counter
import os

class Vector(VectorBase):
    description = "Scans for hardcoded secrets like API keys and passwords in the code."
    tags = ["HARDCODED_SECRETS"]
    wordlist = set()

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.load_wordlist()

    def load_wordlist(self):
        wordlist_path = self.config.get('hardcoded_secrets', {}).get('wordlist_path', 'wordlist.txt')
        try:
            with open(wordlist_path, 'r') as f:
                self.wordlist = {line.strip().lower() for line in f}
        except FileNotFoundError:
            # Silently fail if wordlist is not found.
            pass

    def analyze(self) -> None:
        self.check_hardcoded_secrets()

    def shannon_entropy(self, s: str) -> float:
        if not s:
            return 0.0
        frequency = Counter(s)
        string_length = len(s)
        entropy = 0.0
        for count in frequency.values():
            probability = count / string_length
            entropy -= probability * math.log2(probability)
        return entropy

    def check_hardcoded_secrets(self):
        # Regex-based search
        found_secrets_regex = []
        regexes = {
            "API Key": r"api_key",
            "Password": r"password",
            "AWS Access Key": r"AKIA[0-9A-Z]{16}",
            "Google API Key": r"AIza[0-9A-Za-z_-]{35}",
        }
        strings = self.analysis.get_strings_analysis()
        for s in strings:
            for name, regex in regexes.items():
                if re.search(regex, s, re.IGNORECASE):
                    found_secrets_regex.append((name, s))

        if found_secrets_regex:
            self.writer.startWriter("HARDCODED_SECRETS_REGEX", LEVEL_CRITICAL, "Hardcoded Secrets (Regex-based)",
                                    "The application may contain hardcoded secrets. Please review the following strings:",
                                    ["Security"], vector_name=self.vector_name,
                                    suggestion="Remove hardcoded secrets from the application code. Use a secure storage mechanism like the Android Keystore.",
                                    confidence=5, risk="High")
            for name, secret in found_secrets_regex:
                self.writer.write(f"Potential {name}: {secret}")

        # Entropy-based search
        found_secrets_entropy = []
        url_pattern = re.compile(r'https?://[^\s/$.?#].[^\s]*', re.IGNORECASE)
        entropy_threshold = self.config.get('hardcoded_secrets', {}).get('entropy_threshold', 4.0)

        for s in strings:
            # Filter out some common false positives
            if " " in s or len(s) < 20 or len(s) > 100:
                continue
            
            # Ignore if it's a URL
            if url_pattern.match(s):
                continue

            # Ignore common English words
            if s.lower() in self.wordlist:
                continue

            if "android.permission" in s or "com.android" in s or "androidx" in s:
                continue
            
            if re.match(r"L[a-z0-9/]+;", s): # Dalvik class name
                continue

            try:
                entropy = self.shannon_entropy(s)
                if entropy > entropy_threshold:
                    found_secrets_entropy.append((s, entropy))
            except:
                pass

        if found_secrets_entropy:
            self.writer.startWriter("HARDCODED_SECRETS_ENTROPY", LEVEL_WARNING, "Hardcoded Secrets (Entropy-based)",
                                    "The application may contain hardcoded secrets with high entropy. Please review the following strings:",
                                    ["Security"], vector_name=self.vector_name,
                                    suggestion="Review the identified high-entropy strings to determine if they are secrets. If so, remove them from the code.",
                                    confidence=3, risk="Medium")
            for secret, entropy in found_secrets_entropy:
                self.writer.write(f"Potential secret (entropy: {entropy:.2f}): {secret}")

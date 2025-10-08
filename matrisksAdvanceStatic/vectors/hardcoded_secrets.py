from vector_base import Vector
from constants import *
import re
import math
from collections import Counter
import xml.etree.ElementTree as ET
import os
from utils import resolve_string

class Vector(Vector):
    def __init__(self, writer, apk, vm, vm_analysis, decompiler, call_graph, native_analyzer, args, config, filtering_engine):
        super().__init__(writer, apk, vm, vm_analysis, decompiler, call_graph, native_analyzer, args, config, filtering_engine)
        self.load_wordlist()

    def load_wordlist(self):
        wordlist_path = self.config.get('hardcoded_secrets', {}).get('wordlist_path', 'wordlist.txt')
        try:
            with open(wordlist_path, 'r') as f:
                self.wordlist = {line.strip().lower() for line in f}
        except FileNotFoundError:
            self.wordlist = set()

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

    def analyze(self) -> None:
        found_secrets_regex = []
        found_secrets_entropy = []

        regexes = {
            "Password": re.compile(r'password\s*=\s*["\'](.*?)["\']', re.IGNORECASE),
            "Token": re.compile(r'token\s*=\s*["\'](.*?)["\']', re.IGNORECASE),
            "Secret": re.compile(r'secret\s*=\s*["\'](.*?)["\']', re.IGNORECASE),
            "API Key": re.compile(r'api_key\s*=\s*["\'](.*?)["\']', re.IGNORECASE),
            "AWS Access Key": re.compile(r"AKIA[0-9A-Z]{16}"),
            "Google API Key": re.compile(r"AIza[0-9A-Za-z_-]{35}"),
            "Facebook App ID": re.compile(r"fb_app_id", re.IGNORECASE),
            "Facebook App Secret": re.compile(r"[a-f0-9]{32}", re.IGNORECASE),
            "Twitter API Key": re.compile(r"consumer_key", re.IGNORECASE),
            "Twitter API Secret": re.compile(r"consumer_secret", re.IGNORECASE),
            "Stripe API Key": re.compile(r"sk_live_[0-9a-zA-Z]{24}"),
        }
        
        url_pattern = re.compile(r'https?://[^\s/$.?#].[^\s]*', re.IGNORECASE)
        entropy_threshold = self.config.get('hardcoded_secrets', {}).get('entropy_threshold', 4.0)
        min_len = self.config.get('hardcoded_secrets', {}).get('min_len', 20)
        max_len = self.config.get('hardcoded_secrets', {}).get('max_len', 100)

        for cls in self.analysis.get_classes():
            for method in cls.get_methods():
                if method.is_external():
                    continue
                
                code = method.get_method().get_code()
                if not code:
                    continue

                for ins in code.get_bc().get_instructions():
                    if ins.get_name() == 'const-string':
                        s_value = ins.get_string()
                        for name, regex in regexes.items():
                            if regex.search(s_value):
                                found_secrets_regex.append((name, s_value, method.get_method().get_class_name() + "->" + method.name))
                                continue
                        
                        if not (min_len <= len(s_value) <= max_len) or " " in s_value:
                            continue
                        
                        if url_pattern.match(s_value) or s_value.lower() in self.wordlist:
                            continue

                        if "android.permission" in s_value or "com.android" in s_value or "androidx" in s_value or "android.arch" in s_value or "android.support" in s_value:
                            continue
                        
                        if re.match(r"L[a-z0-9/]+;", s_value):
                            continue

                        try:
                            entropy = self.shannon_entropy(s_value)
                            if entropy > entropy_threshold:
                                found_secrets_entropy.append((s_value, entropy, method.get_method().get_class_name() + "->" + method.name))
                        except Exception:
                            pass

        self.analyze_resource_files(regexes, found_secrets_regex)

        if found_secrets_regex:
            self.writer.startWriter("HARDCODED_SECRETS_REGEX", LEVEL_WARNING, "Potential Hardcoded Secrets (Keyword-based)",
                                    "The application contains strings with keywords like 'password', 'token', or specific API key formats. Review them to ensure no secrets are exposed.",
                                    ["Security"], vector_name=self.vector_name,
                                    suggestion="Remove hardcoded secrets from the application code. Use a secure storage mechanism like the Android Keystore or retrieve them from a secure server.",
                                    confidence=4, risk="High")
            for name, value, location in found_secrets_regex:
                self.writer.write(f"Potential '{name}' found: \"{value}\"")
                self.writer.write(f"  Location: {location}")

        if found_secrets_entropy:
            self.writer.startWriter("HARDCODED_SECRETS_ENTROPY", LEVEL_WARNING, "Potential Hardcoded Secrets (Entropy-based)",
                                    f"The application contains long, high-entropy strings (entropy > {entropy_threshold}) that could be secrets. Please review them.",
                                    ["Security"], vector_name=self.vector_name,
                                    suggestion="Review the identified high-entropy strings to determine if they are secrets. If so, remove them from the code and use a secure storage mechanism.",
                                    confidence=3, risk="Medium")
            for value, entropy, location in found_secrets_entropy:
                self.writer.write(f"Potential secret (entropy: {entropy:.2f}): \"{value}\"")
                self.writer.write(f"  Location: {location}")

    def analyze_resource_files(self, regexes, found_secrets_regex):
        res_dir = os.path.join(self.decompiler.output_dir, "resources", "res")
        if not os.path.exists(res_dir):
            return

        for root, _, files in os.walk(res_dir):
            for file in files:
                if file == "strings.xml":
                    strings_path = os.path.join(root, file)
                    try:
                        tree = ET.parse(strings_path)
                        xml_root = tree.getroot()
                        for string_tag in xml_root.findall("string"):
                            name = string_tag.get("name")
                            value = string_tag.text
                            if name and value:
                                for regex_name, regex in regexes.items():
                                    if regex.search(value):
                                        found_secrets_regex.append((regex_name, value, strings_path))
                    except ET.ParseError:
                        continue

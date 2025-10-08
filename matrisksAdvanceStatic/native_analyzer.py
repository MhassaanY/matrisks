import os
import json
from elftools.elf.elffile import ELFFile

class NativeAnalyzer:
    def __init__(self, apk, output_dir, hooks_file="native_hooks.json"):
        print("NativeAnalyzer.__init__ called")
        self.apk = apk
        self.output_dir = output_dir
        self.hooks = self._load_hooks(hooks_file)
        self.so_files = self._extract_so_files()

    def _load_hooks(self, hooks_file):
        if not os.path.exists(hooks_file):
            return []
        with open(hooks_file, "r") as f:
            return json.load(f).get("hooks", [])

    def _extract_so_files(self):
        so_files = []
        if not os.path.exists(self.output_dir):
            os.makedirs(self.output_dir)

        for f in self.apk.get_files():
            if f.endswith(".so"):
                so_path = os.path.join(self.output_dir, os.path.basename(f))
                with open(so_path, "wb") as fp:
                    fp.write(self.apk.get_file(f))
                so_files.append(so_path)
        return so_files

    def analyze(self):
        analysis_results = {}
        for so_file in self.so_files:
            analysis_results[os.path.basename(so_file)] = self._analyze_so_file(so_file)
        return analysis_results

    def _analyze_so_file(self, so_path):
        analysis = {
            "symbols": {
                "exported": [],
                "imported": []
            },
            "strings": [],
            "hooks": [],
            "jni_mappings": []
        }

        with open(so_path, "rb") as f:
            elffile = ELFFile(f)

            # Get symbols
            symtab = elffile.get_section_by_name('.dynsym')
            if symtab:
                for symbol in symtab.iter_symbols():
                    symbol_name = symbol.name
                    if symbol['st_info']['bind'] in ['STB_GLOBAL', 'STB_WEAK']:
                        analysis["symbols"]["exported"].append(symbol_name)
                        if symbol_name.startswith("Java_"):
                            analysis["jni_mappings"].append(symbol_name)
                    elif symbol['st_info']['type'] == 'STT_FUNC' and symbol['st_shndx'] == 'SHN_UNDEF':
                        analysis["symbols"]["imported"].append(symbol_name)
                    
                    # Check for hooks
                    for hook in self.hooks:
                        if hook["name"] == symbol_name:
                            analysis["hooks"].append(hook)

            # Get strings
            strtab = elffile.get_section_by_name('.rodata')
            if strtab:
                analysis["strings"] = [s.decode(errors='ignore') for s in strtab.data().split(b'\x00')]

        return analysis

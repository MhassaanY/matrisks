import json
import os

class TaintConfig:
    def __init__(self, config_file):
        self.config_file = config_file
        self.sources = []
        self.sinks = []
        self._load_config()

    def _load_config(self):
        if not os.path.exists(self.config_file):
            return

        try:
            with open(self.config_file, "r") as f:
                config = json.load(f)
                self.sources = config.get("sources", [])
                self.sinks = config.get("sinks", [])
        except (IOError, json.JSONDecodeError):
            pass

    def get_sources(self):
        return self.sources

    def get_sinks(self):
        return self.sinks

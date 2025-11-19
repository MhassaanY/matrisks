
"""
Matrisks Dynamic Analyzer
Android malware dynamic analysis with emulator and Frida instrumentation
"""

__version__ = "1.0.0"
__author__ = "Matrisks Framework"

from .core.emulator_manager import EmulatorManager
from .core.orchestrator import DynamicAnalysisOrchestrator
from .instrumentation.frida_manager import FridaManager
from .collectors.api_collector import APICollector
from .collectors.network_collector import NetworkCollector

__all__ = [
    'EmulatorManager',
    'DynamicAnalysisOrchestrator',
    'FridaManager',
    'APICollector',
    'NetworkCollector'
]

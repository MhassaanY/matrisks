from vector_base import VectorBase
from constants import *


class Vector(VectorBase):
    description = "Checks if a framework was used to develop the app, and if so, which one."
    tags = ["FRAMEWORK"]

    XAMARIN_SIGNATURE = {
        "class_name": "Lmono/android/Runtime;",
        "method_name": "register",
        "method_descriptor": "(Ljava/lang/String; Ljava/lang/Class; Ljava/lang/String;)V",
    }

    REACT_NATIVE_SIGNATURE = {
        "class_name": "Lcom/facebook/react/a;"
    }

    FLUTTER_SIGNATURE = {
        "class_name": "Lio/flutter/app/a;"
    }

    def analyze(self) -> None:
        if any([self.check_xamarin(),
                self.check_flutter(),
                self.check_react_native(),
                self.check_ijiami(),
                self.check_bangcle()]):
            return
        else:
            self.writer.startWriter("FRAMEWORK",
                                    LEVEL_INFO,
                                    "App framework identification",
                                    "No frameworks detected (checking for Xamarin, Flutter, React Native). "
                                    "Furthermore, no encryption frameworks were detected (checking for iJiami, Bangcle)",
                                    ['Framework'], vector_name=self.vector_name)

    def check_xamarin(self) -> bool:
        if self.analysis.get_method_analysis_by_name(self.XAMARIN_SIGNATURE["class_name"],
                                                         self.XAMARIN_SIGNATURE["method_name"],
                                                         self.XAMARIN_SIGNATURE["method_descriptor"]):
            self.writer.startWriter("FRAMEWORK",
                                    LEVEL_NOTICE,
                                    "App Framework Identification: Xamarin",
                                    "Application appears to be built with the Xamarin framework.",
                                    ['Framework'], vector_name=self.vector_name,
                                    suggestion="This is an informational finding. No action is required.",
                                    confidence=5, risk="Info")
            return True
        return False

    def check_flutter(self) -> bool:
        if self.analysis.is_class_present(self.FLUTTER_SIGNATURE["class_name"]):
            self.writer.startWriter("FRAMEWORK",
                                    LEVEL_NOTICE,
                                    "App Framework Identification: Flutter",
                                    "Application appears to be built with the Flutter framework.",
                                    ['Framework'], vector_name=self.vector_name,
                                    suggestion="This is an informational finding. No action is required.",
                                    confidence=5, risk="Info")
            return True
        return False

    def check_react_native(self) -> bool:
        if self.analysis.is_class_present(self.REACT_NATIVE_SIGNATURE["class_name"]):
            self.writer.startWriter("FRAMEWORK",
                                    LEVEL_NOTICE,
                                    "App Framework Identification: React Native",
                                    "Application appears to be built with the React Native framework.",
                                    ['Framework'], vector_name=self.vector_name,
                                    suggestion="This is an informational finding. No action is required.",
                                    confidence=5, risk="Info")
            return True
        return False

    def check_ijiami(self) -> bool:
        if any(self.analysis.find_methods("Lcom/shell/NativeApplication;", "load",
                                          r"\(Landroid/app/Application; Ljava/lang/String;\)Z")):
            self.writer.startWriter("FRAMEWORK",
                                    LEVEL_NOTICE,
                                    "App Framework Identification: Ijiami Encryption",
                                    "This app appears to be using the Ijiami Encryption Framework. Analysis may be incomplete.",
                                    ['Framework', 'Obfuscation'], vector_name=self.vector_name,
                                    suggestion="For a complete analysis, provide the unencrypted version of the APK.",
                                    confidence=5, risk="Info")
            return True
        return False

    def check_bangcle(self) -> bool:
        if any(self.analysis.find_methods("Lcom/secapk/wrapper/ACall;",
                                          "getACall",
                                          r"\(\)Lcom/secapk/wrapper/ACall;")):
            self.writer.startWriter("FRAMEWORK",
                                    LEVEL_NOTICE,
                                    "App Framework Identification: Bangcle Encryption",
                                    "This app appears to be using the Bangcle Encryption Framework. Analysis may be incomplete.",
                                    ['Framework', 'Obfuscation'], vector_name=self.vector_name,
                                    suggestion="For a complete analysis, provide the unencrypted version of the APK.",
                                    confidence=5, risk="Info")
            return True
        return False
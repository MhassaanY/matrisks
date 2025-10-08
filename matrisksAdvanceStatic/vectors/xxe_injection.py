from vector_base import Vector
from constants import *
import staticDVM

class Vector(Vector):
    def __init__(self, writer, apk, vm, vm_analysis, decompiler, call_graph, native_analyzer, args, config, filtering_engine):
        super().__init__(writer, apk, vm, vm_analysis, decompiler, call_graph, native_analyzer, args, config, filtering_engine)
    description = "Checks for insecurely configured XML parsers that could be vulnerable to XML External Entity (XXE) injection."
    tags = ["XXE_INJECTION"]

    # Features to prevent XXE. Key: feature string, Value: desired boolean state.
    SECURE_FEATURES = {
        "http://xml.org/sax/features/external-general-entities": False,
        "http://xml.org/sax/features/external-parameter-entities": False,
        "http://apache.org/xml/features/disallow-doctype-decl": True,
    }

    def analyze(self) -> None:
        vulnerable_locations = set()

        # 1. Check for DocumentBuilderFactory
        dbf_methods = self.analysis.find_methods("Ljavax/xml/parsers/DocumentBuilderFactory;", "newDocumentBuilder", "()Ljavax/xml/parsers/DocumentBuilder;")
        for path in staticDVM.get_paths(dbf_methods):
            source_method = path['src_method']
            if not self.is_securely_configured(source_method):
                vulnerable_locations.add(source_method)

        # 2. Check for SAXParserFactory
        spf_methods = self.analysis.find_methods("Ljavax/xml/parsers/SAXParserFactory;", "newSAXParser", "()Ljavax/xml/parsers/SAXParser;")
        for path in staticDVM.get_paths(spf_methods):
            source_method = path['src_method']
            if not self.is_securely_configured(source_method):
                vulnerable_locations.add(source_method)

        if vulnerable_locations:
            self.writer.startWriter("POTENTIAL_XXE_VULNERABILITY", LEVEL_WARNING, "Potential XXE Injection Vulnerability",
                                    "The application uses XML parsers without disabling features that can lead to XML External Entity (XXE) attacks. This can result in information disclosure or denial of service.",
                                    ["Security", "Injection"], vector_name=self.vector_name,
                                    suggestion="Ensure all XML parsers are configured to disable DTDs and external entities. For DocumentBuilderFactory, call setFeature('http://apache.org/xml/features/disallow-doctype-decl', true) before creating the parser.",
                                    confidence=4, risk="High")
            
            for method in sorted(vulnerable_locations, key=lambda m: m.get_class_name()):
                self.writer.write(f"Insecure XML parser created in: {self.writer.simplifyClassPath(method.get_class_name())}->{method.get_name()}")

    def is_securely_configured(self, method) -> bool:
        """
        Analyzes the method's bytecode to see if it calls `setFeature` with secure values.
        This is a heuristic that checks for configuration within the same method.
        Returns True if a secure configuration is found, False otherwise.
        """
        if method.is_external():
            return True # Cannot analyze external code, assume it's safe.

        code = method.get_method().get_code()
        if not code:
            return True

        instructions = list(code.get_bc().get_instructions())
        features_set = {}

        for idx, ins in enumerate(instructions):
            if ins.get_name() == 'invoke-virtual' and ins.get_operands()[-1][1].get_name() == 'setFeature':
                
                register_analyzer = staticDVM.RegisterAnalyzerVMImmediateValue()
                register_analyzer.load_instructions(instructions, idx)
                
                operands = ins.get_operands()
                if len(operands) >= 3:
                    feature_string_reg = operands[1][1]
                    feature_value_reg = operands[2][1]

                    feature_string = register_analyzer.get_register_value(feature_string_reg)
                    feature_value_int = register_analyzer.get_register_value(feature_value_reg)
                    
                    if feature_string is not None and feature_value_int is not None:
                        feature_value = (feature_value_int == 1)
                        features_set[feature_string] = feature_value

        # Check if all required secure features are set correctly
        all_secure = True
        for feature, required_value in self.SECURE_FEATURES.items():
            if features_set.get(feature) != required_value:
                all_secure = False
                break
        
        return all_secure

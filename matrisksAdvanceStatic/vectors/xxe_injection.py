from vector_base import VectorBase
from constants import *
import staticDVM

class Vector(VectorBase):
    description = "Checks for insecurely configured XML parsers that could be vulnerable to XML External Entity (XXE) injection."
    tags = ["XXE_INJECTION"]

    SECURE_FEATURES = {
        "http://xml.org/sax/features/external-general-entities": False,
        "http://xml.org/sax/features/external-parameter-entities": False,
        "http://apache.org/xml/features/disallow-doctype-decl": True,
    }

    def analyze(self) -> None:
        found_vulnerable_parsers = set()

        # Check for DocumentBuilderFactory
        dbf_methods = self.analysis.find_methods("Ljavax/xml/parsers/DocumentBuilderFactory;", "newDocumentBuilder", "()Ljavax/xml/parsers/DocumentBuilder;")
        for path in staticDVM.get_paths(dbf_methods):
            # This is a simplified check. A full implementation would require taint analysis
            # to track the factory from its instantiation to the newDocumentBuilder call,
            # checking all setFeature calls in between.
            # For now, we report any usage as a point of manual review.
            source_method = path['src_method']
            finding = f"Potential XXE vulnerability. XML parser is used in {source_method.get_class_name()}->{source_method.get_name()}. Please manually verify that XXE protection is enabled."
            found_vulnerable_parsers.add(finding)

        # Check for SAXParserFactory
        spf_methods = self.analysis.find_methods("Ljavax/xml/parsers/SAXParserFactory;", "newSAXParser", "()Ljavax/xml/parsers/SAXParser;")
        for path in staticDVM.get_paths(spf_methods):
            source_method = path['src_method']
            finding = f"Potential XXE vulnerability. SAX parser is used in {source_method.get_class_name()}->{source_method.get_name()}. Please manually verify that XXE protection is enabled."
            found_vulnerable_parsers.add(finding)


        if found_vulnerable_parsers:
            self.writer.startWriter("POTENTIAL_XXE_VULNERABILITY", LEVEL_WARNING, "Potential XXE Injection Vulnerability",
                                    "The application uses XML parsers that might be configured insecurely, potentially allowing XML External Entity (XXE) attacks. This can lead to information disclosure or denial of service.",
                                    ["Security", "Injection"], vector_name=self.vector_name,
                                    suggestion="Ensure all XML parsers are configured to disable DTDs and external entities. For DocumentBuilderFactory, call setFeature(\"http://apache.org/xml/features/disallow-doctype-decl\", true).",
                                    confidence=3, risk="Medium")
            
            for finding in sorted(list(found_vulnerable_parsers)):
                self.writer.write(finding)

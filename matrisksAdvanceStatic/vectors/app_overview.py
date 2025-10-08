from vector_base import Vector
from constants import *

class Vector(Vector):
    def __init__(self, writer, apk, vm, vm_analysis, decompiler, call_graph, native_analyzer, args, config, filtering_engine):
        super().__init__(writer, apk, vm, vm_analysis, decompiler, call_graph, native_analyzer, args, config, filtering_engine)
    description = "Provides a high-level overview of the application's attack surface."
    tags = ["APP_OVERVIEW"]

    def analyze(self) -> None:
        self.writer.startWriter("APP_OVERVIEW_SUMMARY", LEVEL_INFO, "Application Attack Surface Overview",
                                "This is a summary of the application's configuration and components, which can help in assessing its overall attack surface.",
                                ["Discovery"], vector_name=self.vector_name,
                                suggestion="Review the listed permissions and exported components to ensure they align with the principle of least privilege.",
                                confidence=5, risk="Info")

        # 1. Manifest Information
        self.writer.write("\n--- Manifest Details ---")
        self.writer.write(f"Package Name: {self.apk.get_package()}")
        self.writer.write(f"Target SDK Version: {self.apk.get_target_sdk_version()}")
        self.writer.write(f"Min SDK Version: {self.apk.get_min_sdk_version()}")
        is_debuggable = self.apk.get_attribute_value('application', 'debuggable') not in (None, "false")
        if is_debuggable:
            self.writer.write("Application is DEBUGGABLE.")

        # 2. Permissions
        self.writer.write("\n--- Declared Permissions ---")
        permissions = self.apk.get_permissions()
        if permissions:
            for perm in sorted(permissions):
                self.writer.write(f"- {perm}")
        else:
            self.writer.write("No permissions declared.")

        # 3. Exported Components
        self.writer.write("\n--- Exported Components (without permission protection) ---")
        exported_components_found = False

        # Activities
        exported_activities = self.get_exported_components('activity')
        if exported_activities:
            exported_components_found = True
            self.writer.write("Exported Activities:")
            for item in exported_activities:
                self.writer.write(f"- {item}")

        # Services
        exported_services = self.get_exported_components('service')
        if exported_services:
            exported_components_found = True
            self.writer.write("Exported Services:")
            for item in exported_services:
                self.writer.write(f"- {item}")

        # Receivers
        exported_receivers = self.get_exported_components('receiver')
        if exported_receivers:
            exported_components_found = True
            self.writer.write("Exported Receivers:")
            for item in exported_receivers:
                self.writer.write(f"- {item}")
        
        # Providers
        # Note: Content providers have different logic for 'exported' attribute.
        # By default, it's false for targetSDK >= 17, true otherwise.

        if not exported_components_found:
            self.writer.write("No exported components without permission protection were found.")

    def get_exported_components(self, component_type: str) -> list:
        exported_items = []
        # Correctly form the getter method name (e.g., get_activities, get_services)
        if component_type == 'activity':
            method_name = 'get_activities'
        else:
            method_name = f"get_{component_type}s"
        
        component_getter = getattr(self.apk, method_name)
        
        for item_name in component_getter():
            is_exported = False
            # Check for intent filters, which implies exported unless explicitly set to false
            if self.apk.get_intent_filters(component_type, item_name):
                if self.apk.get_attribute_value(component_type, 'exported', name=item_name) != "false":
                    is_exported = True
            
            # Check for explicit export="true"
            if self.apk.get_attribute_value(component_type, 'exported', name=item_name) == "true":
                is_exported = True

            if is_exported:
                # Check if it's protected by a permission
                permission = self.apk.get_attribute_value(component_type, 'permission', name=item_name)
                if not permission:
                    exported_items.append(item_name)
        return sorted(exported_items)

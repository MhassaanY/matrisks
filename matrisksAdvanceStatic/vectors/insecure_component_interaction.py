from vector_base import Vector
from constants import *

class Vector(Vector):
    def __init__(self, writer, apk, vm, vm_analysis, decompiler, call_graph, native_analyzer, args, config, filtering_engine):
        super().__init__(writer, apk, vm, vm_analysis, decompiler, call_graph, native_analyzer, args, config, filtering_engine)
    description = "Checks for insecure component interactions, such as exported components without proper protection."
    tags = ["INSECURE_COMPONENT_INTERACTION"]

    def analyze(self) -> None:
        self.check_exported_components()

    def check_exported_components(self):
        # Activities
        exported_activities = []
        for activity_name in self.apk.get_activities():
            is_exported = False
            # Check for intent filters
            if self.apk.get_intent_filters('activity', activity_name):
                if self.apk.get_attribute_value('activity', 'exported', name=activity_name) != "false":
                    is_exported = True
            # Check for explicit export
            if self.apk.get_attribute_value('activity', 'exported', name=activity_name) == "true":
                is_exported = True

            if is_exported:
                permission = self.apk.get_attribute_value('activity', 'permission', name=activity_name)
                if not permission:
                    exported_activities.append(activity_name)

        if exported_activities:
            self.writer.startWriter("EXPORTED_ACTIVITIES_NO_PERMISSION", LEVEL_WARNING, "Exported Activities without Permissions",
                                    "The following activities are exported but not protected by a permission:",
                                    ["Component"], vector_name=self.vector_name)
            for activity in exported_activities:
                self.writer.write(activity)

        # Services
        exported_services = []
        for service_name in self.apk.get_services():
            is_exported = False
            if self.apk.get_intent_filters('service', service_name):
                if self.apk.get_attribute_value('service', 'exported', name=service_name) != "false":
                    is_exported = True
            if self.apk.get_attribute_value('service', 'exported', name=service_name) == "true":
                is_exported = True

            if is_exported:
                permission = self.apk.get_attribute_value('service', 'permission', name=service_name)
                if not permission:
                    exported_services.append(service_name)

        if exported_services:
            self.writer.startWriter("EXPORTED_SERVICES_NO_PERMISSION", LEVEL_WARNING, "Exported Services without Permissions",
                                    "The following services are exported but not protected by a permission:",
                                    ["Component"], vector_name=self.vector_name)
            for service in exported_services:
                self.writer.write(service)

        # Receivers
        exported_receivers = []
        for receiver_name in self.apk.get_receivers():
            is_exported = False
            if self.apk.get_intent_filters('receiver', receiver_name):
                if self.apk.get_attribute_value('receiver', 'exported', name=receiver_name) != "false":
                    is_exported = True
            if self.apk.get_attribute_value('receiver', 'exported', name=receiver_name) == "true":
                is_exported = True

            if is_exported:
                permission = self.apk.get_attribute_value('receiver', 'permission', name=receiver_name)
                if not permission:
                    exported_receivers.append(receiver_name)

        if exported_receivers:
            self.writer.startWriter("EXPORTED_RECEIVERS_NO_PERMISSION", LEVEL_WARNING, "Exported Receivers without Permissions",
                                    "The following receivers are exported but not protected by a permission:",
                                    ["Component"], vector_name=self.vector_name)
            for receiver in exported_receivers:
                self.writer.write(receiver)
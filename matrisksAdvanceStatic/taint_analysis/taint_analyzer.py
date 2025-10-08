import json

class TaintAnalyzer:
    def __init__(self, vm_analysis, index):
        self.vm_analysis = vm_analysis
        self.index = index
        self.sources = []
        self.sinks = []
        self.leaks = []
        self.tainted_params = {}
        self.tainted_return = {}
        self.taint_sources = {}
        self.taint_paths = {}
        self.tainted_fields = {}

    def load_sources_and_sinks(self, sources_and_sinks_path):
        with open(sources_and_sinks_path, 'r') as f:
            data = json.load(f)
            self.sources = data["sources"]
            self.sinks = data["sinks"]

    def analyze(self):
        while True:
            taint_changed = False
            for cls in self.vm_analysis.get_classes():
                for method in cls.get_methods():
                    if method.is_external():
                        continue
                    if self.analyze_method(method):
                        taint_changed = True
            if not taint_changed:
                break
        return self.leaks

    def analyze_method(self, method):
        method_signature = method.get_method().get_class_name() + "->" + method.get_method().name + method.get_method().get_descriptor()
        tainted_registers = set()
        taint_changed = False
        path = []

        if method_signature in self.tainted_params:
            for param_index, (source, path) in self.tainted_params[method_signature].items():
                register = f"p{param_index}"
                tainted_registers.add(register)
                self.taint_sources[register] = source
        code = method.get_method().get_code()
        if not code:
            return False
        
        instructions = list(code.get_bc().get_instructions())
        for idx, ins in enumerate(instructions):
            print(f"Processing instruction: {ins.get_name()} {ins.get_operands()} in {method_signature}")
            if ins.get_name() == 'invoke-virtual':
                operands = ins.get_operands()
                if len(operands) > 2 and isinstance(operands[2], list) and len(operands[2]) > 2:
                    callee_signature = f"{operands[2][0]}->{operands[2][1]}{operands[2][2]}"
                    for source in self.sources:
                        if source["signature"] == callee_signature:
                            if ins.get_output():
                                register = ins.get_output().split(' ')[0]
                                if register not in tainted_registers:
                                    tainted_registers.add(register)
                                    self.taint_sources[register] = source["signature"]
                                    self.taint_paths[register] = [(method_signature, idx)]
                                    taint_changed = True

            if ins.get_name() == 'invoke-virtual':
                operands = ins.get_operands()
                if len(operands) > 2 and isinstance(operands[2], list) and len(operands[2]) > 2:
                    callee_signature = f"{operands[2][0]}->{operands[2][1]}{operands[2][2]}"
                    for sink in self.sinks:
                        if sink["signature"] == callee_signature:
                            for i in range(1, len(operands)):
                                if operands[i][0] == 'v' and operands[i] in tainted_registers:
                                    self.leaks.append({
                                        "source": self.taint_sources[operands[i]],
                                        "sink": sink["signature"],
                                        "method": method_signature,
                                        "path": self.taint_paths[operands[i]] + [(method_signature, idx)]
                                    })

            if ins.get_name().startswith('move'):
                operands = ins.get_operands()
                if len(operands) == 2:
                    dest, src = operands
                    if src in tainted_registers and dest not in tainted_registers:
                        tainted_registers.add(dest)
                        self.taint_sources[dest] = self.taint_sources[src]
                        self.taint_paths[dest] = self.taint_paths[src] + [(method_signature, idx)]
                        taint_changed = True
            elif 0x90 <= ins.get_op_value() <= 0xab: # Arithmetic and Logical Operations (reg, reg)
                operands = ins.get_operands()
                if len(operands) == 3:
                    dest, src1, src2 = operands
                    if (src1 in tainted_registers or src2 in tainted_registers) and dest not in tainted_registers:
                        tainted_registers.add(dest)
                        # For simplicity, we just propagate the taint from the first tainted source.
                        if src1 in tainted_registers:
                            self.taint_sources[dest] = self.taint_sources[src1]
                            self.taint_paths[dest] = self.taint_paths[src1] + [(method_signature, idx)]
                        else:
                            self.taint_sources[dest] = self.taint_sources[src2]
                            self.taint_paths[dest] = self.taint_paths[src2] + [(method_signature, idx)]
                        taint_changed = True
            elif 0x5b <= ins.get_op_value() <= 0x68: # iput/sput instructions
                operands = ins.get_operands()
                value_reg = operands[0]
                if value_reg in tainted_registers:
                    field_info = operands[-1] # e.g., ['Ljava/lang/System;', 'out', 'Ljava/io/PrintStream;']
                    field_signature = f"{field_info[0]}->{field_info[1]}"
                    if field_signature not in self.tainted_fields:
                        self.tainted_fields[field_signature] = (self.taint_sources[value_reg], self.taint_paths[value_reg])
                        taint_changed = True
            elif 0x54 <= ins.get_op_value() <= 0x5a or 0x69 <= ins.get_op_value() <= 0x6f: # iget/sget instructions
                operands = ins.get_operands()
                dest_reg = operands[0]
                field_info = operands[-1]
                field_signature = f"{field_info[0]}->{field_info[1]}"
                if field_signature in self.tainted_fields and dest_reg not in tainted_registers:
                    source, path = self.tainted_fields[field_signature]
                    tainted_registers.add(dest_reg)
                    self.taint_sources[dest_reg] = source
                    self.taint_paths[dest_reg] = path + [(method_signature, idx)]
                    taint_changed = True
            elif 0x4b <= ins.get_op_value() <= 0x51: # aput instructions
                operands = ins.get_operands()
                value_reg = operands[0]
                array_reg = operands[1]
                if value_reg in tainted_registers:
                    tainted_registers.add(array_reg)
                    self.taint_sources[array_reg] = self.taint_sources[value_reg]
                    self.taint_paths[array_reg] = self.taint_paths[value_reg] + [(method_signature, idx)]
                    taint_changed = True
            elif 0x44 <= ins.get_op_value() <= 0x4a: # aget instructions
                operands = ins.get_operands()
                dest_reg = operands[0]
                array_reg = operands[1]
                if array_reg in tainted_registers and dest_reg not in tainted_registers:
                    tainted_registers.add(dest_reg)
                    self.taint_sources[dest_reg] = self.taint_sources[array_reg]
                    self.taint_paths[dest_reg] = self.taint_paths[array_reg] + [(method_signature, idx)]
                    taint_changed = True
            
            if ins.get_name() == 'invoke-virtual':
                operands = ins.get_operands()
                if len(operands) > 2 and isinstance(operands[2], list) and len(operands[2]) > 2:
                    callee_signature = f"{operands[2][0]}->{operands[2][1]}{operands[2][2]}"
                    for i in range(1, len(operands)):
                        if operands[i][0] == 'v' and operands[i] in tainted_registers:
                            if callee_signature not in self.tainted_params:
                                self.tainted_params[callee_signature] = {}
                            if i - 1 not in self.tainted_params[callee_signature]:
                                self.tainted_params[callee_signature][i - 1] = (self.taint_sources[operands[i]], self.taint_paths[operands[i]])
                                taint_changed = True
                    
                    if callee_signature in self.tainted_return and self.tainted_return[callee_signature]:
                        if ins.get_output():
                            register = ins.get_output().split(' ')[0]
                            if register not in tainted_registers:
                                tainted_registers.add(register)
                                source, path = self.tainted_return[callee_signature]
                                self.taint_sources[register] = source
                                self.taint_paths[register] = path + [(method_signature, idx)]
                                taint_changed = True

        for idx, ins in enumerate(instructions):
            if ins.get_name().startswith('return'):
                if len(ins.get_operands()) > 0 and ins.get_operands()[0] in tainted_registers:
                    if method_signature not in self.tainted_return or not self.tainted_return[method_signature]:
                        self.tainted_return[method_signature] = (self.taint_sources[ins.get_operands()[0]], self.taint_paths[ins.get_operands()[0]])
                        taint_changed = True

        return taint_changed
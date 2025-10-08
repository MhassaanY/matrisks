import re


def is_null_or_empty_string(input_string, strip_whitespaces=False):
    if input_string is None:
        return True
    if strip_whitespaces:
        if input_string.strip() == "":
            return True
    else:
        if input_string == "":
            return True
    return False


def get_elements_by_tagname(xml, tagname):
    results = []
    get_elements_by_tagname_sub(xml, tagname, results)
    return results

def get_elements_by_tagname_sub(xml, tagname, results):

    children = xml.getchildren()

    for child in children:
        get_elements_by_tagname_sub(child, tagname, results)

    if xml.tag == tagname:
        results.append(xml)

def resolve_string(method, register):
    """Resolves a constant string from a register."""
    # This is a very basic implementation and only handles simple cases.
    # A more advanced implementation would require a full-fledged symbolic execution engine.
    for ins in method.get_instructions():
        if ins.get_name() == 'const-string' and ins.get_output().startswith(register):
            return ins.get_operands()[1]
    return None
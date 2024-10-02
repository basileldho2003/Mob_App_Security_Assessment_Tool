import yara

def scan_source_code(decompiled_dir):
    rule = """
    rule MaliciousCode {
        strings:
            $a = "malware"
            $b = "exploit"
        condition:
            $a or $b
    }
    """
    yara_rules = yara.compile(source=rule)
    matches = yara_rules.match(decompiled_dir)
    issues = [str(match) for match in matches]
    return issues

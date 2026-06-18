import re

SSH_FAIL_PATTERN = re.compile(
    r'Failed password for (?P<user>\S+) from (?P<src_ip>\S+)'
)
SSH_SUCCESS_PATTERN = re.compile(
    r'Accepted password for (?P<user>\S+) from (?P<src_ip>\S+)'
)

def parse_auth_line(line: str):
    fail_match = SSH_FAIL_PATTERN.search(line)
    if fail_match:
        data = fail_match.groupdict()
        data["status"] = "failure"
        return data
       
    success_match = SSH_SUCCESS_PATTERN.search(line)
    if success_match:
        data = success_match.groupdict()
        data["status"] = "success"
        return data
       
    return None

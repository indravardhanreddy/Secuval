import re

pattern = re.compile(r'(?i)<script')
test_string = '{"name": "<script>alert(\'xss\')</script>"}'

print('Pattern matches:', bool(pattern.search(test_string)))
print('Test string:', repr(test_string))

# Test the Rust patterns
patterns = [
    r"(?i)<script",
    r"(?i)on(click|error|load|mouseover|mouseout|keydown|keyup|keypress|submit|change|focus|blur)\s*=",
    r"(?i)javascript:",
    r"(?i)vbscript:",
]

for p in patterns:
    regex = re.compile(p)
    if regex.search(test_string):
        print(f"Pattern {p} matches")

output = """garak LLM vulnerability scanner v0.13.3 ( https://github.com/NVIDIA/garak ) at 2026-01-22T15:46:58.199216
probes: ansiescape 🌟
probes: ansiescape.AnsiEscaped
probes: ansiescape.AnsiRaw
"""
probes = []
for line in output.splitlines():
    line = line.strip()
    print(f"Checking line: '{line}'")
    if line.startswith("probes:"):
        parts = line.split("probes:", 1)[1].strip().split()
        if parts:
            probe_name = parts[0]
            probes.append(probe_name)
print(probes)

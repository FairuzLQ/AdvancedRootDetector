"""Checks emulator lab JSON results against expectations.json and prints a Markdown report.

Usage: check.py <out-dir> <api-level>   (report goes to stdout; exit 1 on violations)
"""
import json
import os
import sys

out_dir, api = sys.argv[1], sys.argv[2]
here = os.path.dirname(os.path.abspath(__file__))
expectations = json.load(open(os.path.join(here, "expectations.json")))

lines = [f"## Emulator lab — API {api}", "",
         "| Scenario | Result | isRooted | Score | Indicators |", "|---|---|---|---|---|"]
details, failed = [], False
for name in sorted(f[:-5] for f in os.listdir(out_dir) if f.endswith(".json")):
    data = json.load(open(os.path.join(out_dir, name + ".json")))
    exp = expectations.get(name, {})
    if "error" in data:
        lines.append(f"| {name} | FAIL ({data['error']}) | – | – | – |")
        failed = True
        continue
    ids = [i["id"] for i in data["indicators"]]
    problems = [f"missing `{m}`" for m in exp.get("must", []) if m not in ids]
    problems += [f"unexpected `{m}`" for m in exp.get("mustnot", []) if m in ids]
    failed |= bool(problems)
    result = "PASS" if not problems else "FAIL: " + ", ".join(problems)
    lines.append(f"| {name} | {result} | {data['isRooted']} | {data['riskScore']} | "
                 + ", ".join(f"`{i}`" for i in ids) + " |")
    details.append(f"### {name}")
    if exp.get("note"):
        details.append(f"> {exp['note']}")
    for ind in data["indicators"]:
        details.append(f"- **{ind['risk']}** `{ind['id']}` — {ind['title']}")
        for ev in ind["evidence"][:3]:
            details.append(f"  - `{str(ev)[:160]}`")
    details.append("")

print("\n".join(lines + [""] + details))
sys.exit(1 if failed else 0)

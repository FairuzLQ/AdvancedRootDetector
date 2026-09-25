"""Picks Firebase Test Lab devices and prints `--device ...` arguments for gcloud.

Chooses up to N physical devices (default 3, env FTL_PHYSICAL) from different manufacturers,
each on its newest supported Android version, plus up to M virtual devices (env FTL_VIRTUAL,
default 0). Keeps a run inside the free Spark-plan daily quota.

Usage: gcloud firebase test android models list --format=json | python3 pick_devices.py
"""
import json
import os
import sys

physical_n = int(os.environ.get("FTL_PHYSICAL", "3"))
virtual_n = int(os.environ.get("FTL_VIRTUAL", "0"))
models = json.load(sys.stdin)


def usable(m):
    tags = [t.lower() for t in m.get("tags", [])]
    return m.get("supportedVersionIds") and not any("deprecated" in t or "preview" in t for t in tags)


def newest(m):
    return max(m["supportedVersionIds"], key=lambda v: int(v) if v.isdigit() else 0)


def pick(form, n):
    chosen, brands = [], set()
    if n <= 0:
        return chosen
    cands = [m for m in models if m.get("form") == form and usable(m)]
    cands.sort(key=lambda m: -int(newest(m)) if newest(m).isdigit() else 0)
    for m in cands:
        brand = (m.get("manufacturer") or m["id"]).lower()
        if brand in brands:
            continue
        brands.add(brand)
        chosen.append(f"--device=model={m['id']},version={newest(m)}")
        if len(chosen) >= n:
            break
    return chosen


args = pick("PHYSICAL", physical_n) + pick("VIRTUAL", virtual_n)
if not args:
    sys.exit("no usable Test Lab devices found")
print(" ".join(args))

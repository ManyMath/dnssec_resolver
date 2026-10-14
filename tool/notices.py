import json
import re
import subprocess
import sys
from pathlib import Path

root = Path(__file__).resolve().parents[1]
metadata = json.loads(subprocess.check_output(
    ["cargo", "metadata", "--locked", "--format-version", "1",
     "--manifest-path", str(root / "native/Cargo.toml")]))
packages = {p["id"]: p for p in metadata["packages"]}
nodes = {n["id"]: n for n in metadata["resolve"]["nodes"]}
shipped, queue = set(), [metadata["resolve"]["root"]]
while queue:
    node = nodes[queue.pop()]
    for dep in node["deps"]:
        if dep["pkg"] not in shipped and any(k["kind"] != "dev" for k in dep["dep_kinds"]):
            shipped.add(dep["pkg"])
            queue.append(dep["pkg"])

license_file = re.compile(r"^(LICEN[CS]E|COPYING|NOTICE|UNLICENSE)", re.I)
groups, missing = {}, []
for package in sorted((packages[i] for i in shipped), key=lambda p: (p["name"], p["version"])):
    directory = Path(package["manifest_path"]).parent
    files = sorted(
        (f for f in directory.rglob("*") if f.is_file() and license_file.match(f.name)
         and not {"tests", "benches", "examples", "target"} & set(f.relative_to(directory).parts)),
        key=lambda f: (len(f.relative_to(directory).parts), str(f)))
    expression = package.get("license") or ""
    mit = [f for f in files if "MIT" in f.name.upper() and f.parent == directory]
    if mit and re.fullmatch(r"[\w.\-+ ]+", expression) and "MIT" in expression.split(" OR "):
        files = mit
    authors = directory / "AUTHORS"
    if not files and authors.is_file() and "Permission is hereby granted" in authors.read_text():
        files = [authors]
    if not files:
        missing.append(f"{package['name']} {package['version']} ({expression})")
        continue
    text = "\n\n".join(
        (f"{f.relative_to(directory)}:\n\n" if f.parent != directory else "")
        + f.read_text(errors="replace").strip() for f in files)
    groups.setdefault(text, []).append(f"{package['name']} {package['version']}")
if missing:
    sys.exit("No license file for: " + ", ".join(missing))

rule = "-" * 80
output = ["dnssec_resolver", "", (root / "LICENSE").read_text().strip()]
for text, names in sorted(groups.items(), key=lambda item: item[1][0]):
    output += [rule, *names, "", text]
(root / "NOTICES").write_text("\n".join(output) + "\n")
print(f"NOTICES: {sum(map(len, groups.values()))} crates in {len(groups)} license groups")

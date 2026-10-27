"""Regenerate Theia's Eclipse .classpath (GhidraDev format) for a given Ghidra install.

Usage: python gen_classpath.py <ghidra_install_dir> [<theia_dir>] [java_ee, default JavaSE-25]
Keeps the existing src/con/output entries, replaces every Ghidra lib entry.
"""
import re
import sys
from pathlib import Path

ghidra = Path(sys.argv[1]).resolve()
theia = Path(sys.argv[2]).resolve() if len(sys.argv) > 2 else Path(__file__).resolve().parent.parent
java_ee = sys.argv[3] if len(sys.argv) > 3 else "JavaSE-25"

cp_file = theia / ".classpath"
raw = cp_file.read_bytes()
newline = "\r\n" if b"\r\n" in raw else "\n"
text = raw.decode("utf-8")

head = [l for l in text.splitlines() if 'kind="src"' in l or 'kind="con"' in l]
# Use an execution environment instead of a GhidraDev-named VM so any Eclipse/jdtls resolves it.
head = [re.sub(r"StandardVMType/[^\"]+", "StandardVMType/" + java_ee, l) for l in head]

javadoc = "jar:file:/" + str(ghidra / "docs" / "GhidraAPI_javadoc.zip") + "!/api/"
libs = []
for jar in sorted((ghidra / "Ghidra").glob("**/lib/*.jar"), key=lambda p: p.as_posix().lower()):
    src = jar.with_name(jar.stem + "-src.zip")
    attrs = f'path="{jar.as_posix()}"'
    if src.exists():
        attrs += f' sourcepath="{src.as_posix()}"'
    libs += [
        f"\t<classpathentry kind=\"lib\" {attrs}>",
        "\t\t<attributes>",
        f"\t\t\t<attribute name=\"javadoc_location\" value=\"{javadoc}\"/>",
        "\t\t</attributes>",
        "\t</classpathentry>",
    ]

out = ['<?xml version="1.0" encoding="UTF-8"?>', "<classpath>", *head, *libs,
       '\t<classpathentry kind="output" path="bin/main"/>', "</classpath>"]
cp_file.write_bytes((newline.join(out) + newline).encode("utf-8"))
print(f"wrote {cp_file}: {len(libs) // 5} Ghidra jars from {ghidra}")

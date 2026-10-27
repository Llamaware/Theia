"""Renumber Theia's SLEIGH bytecode constructors to another V8 version's BYTECODE_LIST.

Usage: python remap_opcodes.py <v8_src> [<languages_dir>] [--write]

Each constructor line ":Name[.Wide|.ExtraWide] ... op = 0xNN" gets the opcode of Name in the
new list (bytecodes are numbered by their position). Without --write it only reports. Also
lists V8 bytecodes that have no constructor and constructors whose bytecode is gone; add or
remove those by hand, then run check_opcodes.py for operand lengths and kinds.
"""
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from check_opcodes import UNENCODED, v8_bytecodes  # noqa: E402

CTOR = re.compile(r"^(:(\w+)(?:\.\w+)?\b[^\n]*?\bop\s*=\s*)(0x[0-9a-fA-F]+)", re.M)


def main():
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    write = "--write" in sys.argv
    lang = Path(args[1]) if len(args) > 1 else Path(__file__).resolve().parent.parent / "data/languages"
    opcodes = {name: i for i, (name, _) in enumerate(v8_bytecodes(args[0]))}
    seen, gone, changed = set(), set(), 0
    for f in sorted(lang.iterdir()):
        if f.suffix not in (".slaspec", ".sinc"):
            continue
        raw = f.read_bytes().decode("utf-8")

        def renumber(m):
            nonlocal changed
            name = m.group(2)
            seen.add(name)
            if name not in opcodes:
                gone.add(name)
                return m.group(0)
            new = "0x%02x" % opcodes[name]
            if int(m.group(3), 16) != opcodes[name]:
                changed += 1
            return m.group(1) + new

        out = CTOR.sub(renumber, raw)
        if write and out != raw:
            f.write_bytes(out.encode("utf-8"))
    print("%d constructor opcode(s) %s" % (changed, "rewritten" if write else "would change (use --write)"))
    for name in sorted(gone):
        print("REMOVED  %s: no longer a V8 bytecode" % name)
    for name, op in sorted(opcodes.items(), key=lambda x: x[1]):
        if name not in seen and not UNENCODED.match(name):
            print("NEW      0x%02X %s: needs constructors" % (op, name))


if __name__ == "__main__":
    main()

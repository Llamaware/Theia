"""Check Theia's SLEIGH bytecode constructors against V8's BYTECODE_LIST.

Usage: python check_opcodes.py <v8_src> [<languages_dir>]

For every V8 bytecode (opcode = position in BYTECODE_LIST) and operand scale (plain, Wide,
ExtraWide) it checks that each SLEIGH constructor of that mnemonic has the right opcode,
consumes the number of bytes V8 encodes, and has register/number operands in V8's order.
Reports missing constructors and mnemonics that are not V8 bytecodes. Exit status is the
number of problems (0 = clean).
"""
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from v8_macros import Macros  # noqa: E402

FIXED = {"Flag8": 1, "IntrinsicId": 1, "RuntimeId": 2}  # operand types that do not scale
SCALES = {"": 1, ".Wide": 2, ".ExtraWide": 4}
REGISTERS = {"Reg", "RegList", "RegPair", "RegOut", "RegOutList", "RegOutPair", "RegOutTriple"}
UNENCODED = re.compile(r"^(Wide|ExtraWide|Debugger|DebugBreak.*)$")  # never in a code cache


def v8_bytecodes(v8_src):
    entries = Macros(v8_src, ["interpreter/bytecodes.h"]).expand("BYTECODE_LIST")
    return [(e[0], [o.split("::k")[1] for o in e[2:]]) for e in entries]


class Sleigh:
    def __init__(self, lang_dir):
        text = "\n".join(re.sub(r"#[^\n]*", "", f.read_text())
                         for f in sorted(Path(lang_dir).iterdir()) if f.suffix in (".slaspec", ".sinc"))
        self.size = {}  # token field -> bytes (context fields: 0)
        for m in re.finditer(r"define token \w+\((\d+)\)(.*?);", text, re.S):
            for f in re.findall(r"^\s*(\w+)\s*=", m.group(2), re.M):
                self.size[f] = int(m.group(1)) // 8
        for m in re.finditer(r"define context \w+(.*?);", text, re.S):
            for f in re.findall(r"^\s*(\w+)\s*=", m.group(1), re.M):
                self.size[f] = 0
        self.tables, self.instructions = {}, {}
        for m in re.finditer(r"^(\w*):(\S*)[^\n]*?\bis\b(.*?)[{\[]", text, re.M):
            table, mnemonic = m.group(1), m.group(2)
            groups = [g.strip() for g in m.group(3).split(";") if g.strip()]
            if table:
                self.tables.setdefault(table, []).append(groups)
            elif not mnemonic.startswith("^"):  # root wrappers such as the try-region one
                self.instructions.setdefault(mnemonic, []).append(groups)

    def _components(self, group):
        return [c.strip("() ") for c in group.split("&") if c.strip("() ")]

    def _field(self, comp):
        return re.split(r"[=!<>]", comp)[0].strip()

    def length(self, groups, depth=0):
        """Bytes a pattern consumes; the &-components of a group overlay the same token."""
        total = 0
        for g in groups:
            sizes = [0]
            for c in self._components(g):
                name = self._field(c)
                if name in self.size:
                    sizes.append(self.size[name])
                elif name in self.tables and depth < 4:
                    sizes.append(max(self.length(alt, depth + 1) for alt in self.tables[name]))
            total += max(sizes)
        return total

    def opcode(self, groups):
        for g in groups:
            for c in self._components(g):
                m = re.match(r"op\s*=\s*(\w+)$", c)
                if m:
                    return int(m.group(1), 0)
        return None

    def kinds(self, groups, depth=0):
        """Operand kinds in order: r = register byte(s), n = number."""
        out = []
        for g in groups:
            for c in self._components(g):
                name = self._field(c)
                if name in ("op", "wide") or name.endswith("Pad") or self.size.get(name, 1) == 0:
                    continue
                if name in self.size:
                    out.append("r" if name == "kReg" else "n")
                    break
                if name in self.tables and depth < 4:
                    out += self.kinds(self.tables[name][0], depth + 1)
                    break
        return out


def main():
    v8_src = sys.argv[1]
    lang = Path(sys.argv[2]) if len(sys.argv) > 2 else Path(__file__).resolve().parent.parent / "data/languages"
    s = Sleigh(lang)
    bytecodes = v8_bytecodes(v8_src)
    problems = 0

    def report(msg):
        nonlocal problems
        print(msg)
        problems += 1

    for opcode, (name, ops) in enumerate(bytecodes):
        if UNENCODED.match(name):
            continue
        for suffix, scale in SCALES.items():
            if suffix and all(o in FIXED for o in ops):
                continue  # V8 never prefixes a bytecode without scalable operands
            expected = 1 + sum(FIXED.get(o, scale) for o in ops) + (1 if suffix else 0)
            kinds = "".join("r" if o in REGISTERS else "n" for o in ops)
            alts = s.instructions.get(name + suffix)
            if not alts:
                report("MISSING  0x%02X %s%s (%s)" % (opcode, name, suffix, ", ".join(ops) or "no operands"))
                continue
            for groups in alts:
                op, size, got = s.opcode(groups), s.length(groups), "".join(s.kinds(groups))
                if op != opcode:
                    report("OPCODE   %s%s: SLEIGH op=%s, V8 0x%02X" % (name, suffix, op, opcode))
                if size != expected:
                    report("LENGTH   0x%02X %s%s: SLEIGH %d bytes, V8 %d (%s)" % (opcode, name, suffix, size, expected, ", ".join(ops)))
                elif got != kinds:
                    report("OPERANDS 0x%02X %s%s: SLEIGH %s, V8 %s (%s) [r=register n=number]" % (opcode, name, suffix, got, kinds, ", ".join(ops)))
    names = {n for n, _ in bytecodes}
    for mnemonic in sorted(s.instructions):
        if mnemonic.split(".")[0] not in names:
            report("EXTRA    %s (not a V8 bytecode)" % mnemonic)
    print("%d problem(s)" % problems)
    return min(problems, 255)


if __name__ == "__main__":
    sys.exit(main())

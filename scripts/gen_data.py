"""Generate Theia's data/*.json tables from a V8 source tree.

Usage: python gen_data.py <v8_src> <out_dir> [all|roots|builtins|jsruns|runtime|intrinsics]
                          [--undef V8_INTL_SUPPORT] [--define SYMBOL] [--old <data_dir>]

<v8_src> is V8's src/ directory at the targeted version. Tables are written to <out_dir>;
point it at Theia's data/ to replace them. Runtime function argument lists are carried over
by name from --old (default: <out_dir>), new functions get placeholders from their arg count.

Theia indexes each table by position, so the order is V8's enum order:
  v8_roots.json       Heap::RootListIndex       heap/heap.h, heap-symbols.h, accessors.h, objects.h
  v8_builtins.json    Builtins::Name            builtins/builtins-definitions.h
  v8_jsruns.json      Context::Field            contexts.h (header slots + NATIVE_CONTEXT_FIELDS)
  v8_funcs.json       Runtime::FunctionId       runtime/runtime.h (FOR_EACH_INTRINSIC, runtime part)
  v8_intrinsics.json  IntrinsicsHelper::IntrinsicId  interpreter/interpreter-intrinsics.h
"""
import argparse
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from v8_macros import DEFAULT_DEFINES, Macros  # noqa: E402


def unquote(s):
    return json.loads(s) if s.startswith('"') else s


def roots(v8, defines):
    m = Macros(v8, ["heap/heap.h", "heap-symbols.h", "accessors.h", "objects.h"], defines)
    out = []
    for t, name, camel in m.expand("STRONG_ROOT_LIST"):
        out.append({"Name": camel, "Type": t.lower()})
    for name, value in m.expand("INTERNALIZED_STRING_LIST"):
        out.append({"Name": name, "Type": "string", "Value": unquote(value)})
    for (name,) in m.expand("PRIVATE_SYMBOL_LIST"):
        out.append({"Name": name, "Type": "symbol"})
    for lst in ("PUBLIC_SYMBOL_LIST", "WELL_KNOWN_SYMBOL_LIST"):
        for name, _ in m.expand(lst):
            out.append({"Name": name, "Type": "symbol"})
    for _, accessor in m.expand("ACCESSOR_INFO_LIST"):
        out.append({"Name": accessor, "Type": "accessor"})
    for _, name, _ in m.expand("STRUCT_LIST"):
        out.append({"Name": name, "Type": "map"})
    if "DATA_HANDLER_LIST" in m.macros:
        for _, _, _, name in m.expand("DATA_HANDLER_LIST"):
            out.append({"Name": name, "Type": "map"})
    out.append({"Name": "kStringTableRootIndex", "Type": "string_table"})
    for t, name, camel in m.expand("SMI_ROOT_LIST"):
        out.append({"Name": camel, "Type": t.lower()})
    # the empty string is a strong root, not an internalized-string entry
    for r in out:
        if r["Name"] == "empty_string":
            r["Value"] = ""
    return out


def builtins(v8, defines):
    m = Macros(v8, ["builtins/builtins-definitions.h"], defines)
    return [args[0] for args in m.expand("BUILTIN_LIST_ALL")]


def jsruns(v8, defines):
    m = Macros(v8, ["contexts.h"], defines)
    text = (Path(v8) / "contexts.h").read_text(encoding="utf-8")
    enum = text[text.index("enum Field {"):]
    header = re.findall(r"^\s*(\w+_INDEX),", enum[:enum.index("NATIVE_CONTEXT_FIELDS")], re.M)
    out = [{"Name": h, "Type": "Field"} for h in header]
    out += [{"Name": name, "Type": t} for _, t, name in m.expand("NATIVE_CONTEXT_FIELDS")]
    return out


def runtime(v8, defines, old):
    m = Macros(v8, ["runtime/runtime.h"], defines)
    args = {}
    if old and (Path(old) / "v8_funcs.json").exists():
        args = {e["Name"]: e["Args"] for e in json.loads((Path(old) / "v8_funcs.json").read_text())}
    out = []
    for entry in m.expand("FOR_EACH_INTRINSIC", leaf="@"):
        name, nargs = entry[0], int(entry[1])
        key = "k" + name
        if key not in args:
            args[key] = [{"Name": "..."}] if nargs < 0 else \
                [{"Name": "arg%d" % i, "Type": "Object"} for i in range(nargs)]
        out.append({"Name": key, "Args": args[key]})
    return out


def intrinsics(v8, defines):
    m = Macros(v8, ["interpreter/interpreter-intrinsics.h"], defines)
    return [args[0] for args in m.expand("INTRINSICS_LIST")]


def write(path, items):
    lines = ",\n".join("    " + json.dumps(i, ensure_ascii=False) for i in items)
    path.write_text("[\n" + lines + "\n]\n", encoding="utf-8", newline="\n")
    print("%-20s %d entries" % (path.name, len(items)))


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("v8_src")
    ap.add_argument("out_dir")
    ap.add_argument("table", nargs="?", default="all",
                    choices=["all", "roots", "builtins", "jsruns", "runtime", "intrinsics"])
    ap.add_argument("--define", action="append", default=[])
    ap.add_argument("--undef", action="append", default=[])
    ap.add_argument("--old", help="data dir to take runtime argument lists from (default: out_dir)")
    a = ap.parse_args()
    defines = (DEFAULT_DEFINES | set(a.define)) - set(a.undef)
    out = Path(a.out_dir)
    out.mkdir(parents=True, exist_ok=True)
    jobs = {
        "roots": ("v8_roots.json", lambda: roots(a.v8_src, defines)),
        "builtins": ("v8_builtins.json", lambda: builtins(a.v8_src, defines)),
        "jsruns": ("v8_jsruns.json", lambda: jsruns(a.v8_src, defines)),
        "runtime": ("v8_funcs.json", lambda: runtime(a.v8_src, defines, a.old or a.out_dir)),
        "intrinsics": ("v8_intrinsics.json", lambda: intrinsics(a.v8_src, defines)),
    }
    for key, (fname, fn) in jobs.items():
        if a.table in ("all", key):
            write(out / fname, fn())


if __name__ == "__main__":
    sys.exit(main())

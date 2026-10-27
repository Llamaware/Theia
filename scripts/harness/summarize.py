"""Summarize a run.py output directory, or compare two.

Usage: python summarize.py <run_dir> [<other_run_dir>]

Totals per run (functions, instructions, error bookmarks, decompile failures from TheiaDump;
import failures and V8RefsAnalyzer errors from the headless logs; failed functions in .js
output) and, when comparing, every sample whose numbers differ.
"""
import re
import sys
from pathlib import Path

DUMP = ("functions", "instructions", "error bookmarks", "decompile failures")


def load(run):
    rows = {}
    for log in sorted(Path(run).glob("*.headless.log")):
        name = log.name[:-len(".headless.log")]
        text = log.read_text(errors="replace")
        m = re.search(r"Something went wrong!\s*\n(.*)", text)
        row = {
            "import failures": int(m is not None),
            "analyzer errors": len(re.findall(r"ERROR Analysis Task: V8RefsAnalyzer", text)),
            "import error": m.group(1).strip() if m else "",
        }
        dump = Path(run) / (name + ".txt")
        if dump.exists():
            for line in dump.read_text(errors="replace").splitlines():
                m = re.match(r"### (.+?): (\d+)$", line)
                if m and m.group(1) in DUMP:
                    row[m.group(1)] = int(m.group(2))
        js = Path(run) / (name + ".js")
        if js.exists():
            row["js failures"] = js.read_text(errors="replace").count(": decompilation failed")
        rows[name] = row
    return rows


METRICS = DUMP + ("import failures", "analyzer errors", "js failures")


def totals(rows):
    return {k: sum(r.get(k, 0) for r in rows.values()) for k in METRICS}


def main():
    a = load(sys.argv[1])
    ta = totals(a)
    if len(sys.argv) == 2:
        print("%s: %d files" % (sys.argv[1], len(a)))
        for k, v in ta.items():
            print("  %-20s %d" % (k, v))
        for name, r in a.items():
            if r["import failures"]:
                print("  IMPORT FAILED %s: %s" % (name, r["import error"]))
        return
    b = load(sys.argv[2])
    tb = totals(b)
    print("%-20s %14s %14s" % ("metric", Path(sys.argv[1]).name, Path(sys.argv[2]).name))
    for k in METRICS:
        print("  %-18s %14d %14d" % (k, ta[k], tb[k]))
    for name in sorted(set(a) | set(b)):
        ra, rb = a.get(name, {}), b.get(name, {})
        diffs = ["%s: %s -> %s" % (k, ra.get(k, "-"), rb.get(k, "-")) for k in METRICS if ra.get(k) != rb.get(k)]
        if diffs:
            print("  %s: %s" % (name, "; ".join(diffs)))


if __name__ == "__main__":
    main()

"""Import .bin files headlessly with a given Theia build and dump the results.

Usage: python run.py <ghidra_dir> <theia_zip> <out_dir> [samples_dir] [--mode dump|nodecomp|js]
                     [--script Probe.java [args...]] [--timeout SECONDS]

samples_dir (default: Theia's samples/) is searched recursively for *.bin. Per sample writes:
  <name>.txt           TheiaDump: metrics, signatures, disassembly, decompiled C   (dump, nodecomp)
  <name>.js            DecompileToJS output                                        (js)
  <name>.headless.log  Ghidra's log
  <name>.<Probe>.txt   with --script: output of that script from this folder, which gets
                       the output file and any further arguments
  <name>.loader.log / .analyzer.log   Theia's logs
Ghidra runs with its user settings in <out_dir>/settings, where the zip is installed, so
neither the Ghidra install nor your own profile and extensions are touched.
"""
import argparse
import os
import shutil
import subprocess
import sys
import time
import zipfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
SKIP = {"snapshot_blob.bin", "natives_blob.bin"}


def ghidra_version(ghidra):
    props = dict(line.split("=", 1) for line in (ghidra / "Ghidra/application.properties").read_text().splitlines()
                 if "=" in line and not line.startswith("#"))
    return "ghidra_%s_%s" % (props["application.version"], props["application.release.name"])


def headless(ghidra, settings, args, log, timeout):
    vmargs = "-XX:ParallelGCThreads=2 -XX:CICompilerCount=2 -Dapplication.settingsdir=%s" % settings
    launch = ghidra / "support" / ("launch.bat" if os.name == "nt" else "launch.sh")
    cmd = [str(launch), "fg", "jdk", "Ghidra-Headless", "2G", vmargs,
           "ghidra.app.util.headless.AnalyzeHeadless"] + args
    if os.name == "nt":
        cmd = ["cmd", "/c"] + cmd
    with open(log, "w", encoding="utf-8", errors="replace") as out:
        try:
            return subprocess.run(cmd, stdin=subprocess.DEVNULL, stdout=out, stderr=subprocess.STDOUT,
                                  timeout=timeout).returncode
        except subprocess.TimeoutExpired:
            out.write("\n*** timed out after %d s\n" % timeout)
            return -1


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("ghidra")
    ap.add_argument("theia_zip")
    ap.add_argument("out")
    ap.add_argument("samples", nargs="?", default=str(HERE.parent.parent / "samples"))
    ap.add_argument("--mode", choices=["dump", "nodecomp", "js"], default="dump")
    ap.add_argument("--script", nargs="+", metavar=("SCRIPT", "ARG"), help="run this script instead")
    ap.add_argument("--timeout", type=int, default=3600)
    a = ap.parse_args()

    ghidra = Path(a.ghidra).resolve()
    out = Path(a.out).resolve()
    settings = out / "settings"
    ext_dir = settings / "ghidra" / ghidra_version(ghidra) / "Extensions"
    if (ext_dir / "Theia").exists():
        shutil.rmtree(ext_dir / "Theia")
    ext_dir.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(a.theia_zip) as z:
        z.extractall(ext_dir)
    project = out / "project"
    project.mkdir(parents=True, exist_ok=True)
    theia_logs = settings / "ghidra" / ghidra_version(ghidra) / "Theia"

    bins = sorted(p for p in Path(a.samples).rglob("*.bin") if p.name not in SKIP)
    for b in bins:
        name = b.stem
        if a.script:
            result = out / ("%s.%s.txt" % (name, Path(a.script[0]).stem))
            post = ["-postScript", a.script[0], str(result)] + a.script[1:]
        elif a.mode == "js":
            result = out / (name + ".js")
            post = ["-postScript", "DecompileToJS.java", str(result)]
        else:
            result = out / (name + ".txt")
            post = ["-postScript", "TheiaDump.java", str(result), "nodecomp" if a.mode == "nodecomp" else "full"]
        start = time.time()
        code = headless(ghidra, settings, [str(project), "theia_harness", "-import", str(b), "-overwrite",
                                           "-scriptPath", str(HERE)] + post + ["-deleteProject"],
                        out / (name + ".headless.log"), a.timeout)
        for kind in ("loader", "analyzer"):
            log = theia_logs / (kind + ".log")
            if log.exists():
                shutil.move(str(log), str(out / ("%s.%s.log" % (name, kind))))
        status = "" if code == 0 and result.exists() else "  FAILED (see %s.headless.log)" % name
        print("%-32s %5.0f s%s" % (name, time.time() - start, status))
        if not a.script and result.suffix == ".txt" and result.exists():
            for line in result.read_text(encoding="utf-8", errors="replace").splitlines():
                if line.startswith("### ") and "analyzers" not in line:
                    print("    " + line[4:])


if __name__ == "__main__":
    sys.exit(main())

# Scripts

These are the tools for retargeting Theia at another V8 version (see `docs/FORKING.md`) and for testing a build. They need Python 3.9+ and have no dependencies. `<v8>` is the V8 `src/` directory of the targeted version.

## V8 tables and bytecodes

| Script | Use |
| --- | --- |
| `gen_data.py <v8> <out_dir> [table] [--define X] [--undef X] [--old dir]` | Writes `data/v8_*.json` in V8 enum order: `roots`, `builtins`, `jsruns`, `runtime`, `intrinsics` or `all`. Runtime argument lists carry over by name from `--old`, which defaults to `out_dir`. `V8_INTL_SUPPORT` is defined by default. |
| `remap_opcodes.py <v8> [lang_dir] [--write]` | Renumbers the SLEIGH constructors (`op = 0x..`) by mnemonic, and lists bytecodes added to or removed from V8. |
| `check_opcodes.py <v8> [lang_dir]` | Checks every constructor's opcode, length per scale and register/number operand order against `BYTECODE_LIST`. The exit status is the problem count. |
| `v8_macros.py` | The library the scripts above share: expands V8 X-macro lists, with `#if` support. |
| `gen_classpath.py <ghidra> [theia_dir] [JavaSE-NN]` | Regenerates the Eclipse/jdtls `.classpath` for a Ghidra install. |

## Harness (`harness/`)

`run.py` imports every `*.bin` under a directory headlessly. Ghidra gets a separate user settings directory under `<out>`, where the build is installed, so neither your Ghidra install nor your profile is touched.

```
python harness/run.py <ghidra> <theia.zip> <out> [samples_dir] [--mode dump|nodecomp|js]
                      [--script Probe.java [args...]] [--timeout s]
python harness/summarize.py <out> [<other_out>]
```

| Mode | Output per sample |
| --- | --- |
| `dump` (default) | `<name>.txt`: metrics, signatures, disassembly and decompiled C (`TheiaDump.java`). Deterministic, so runs can be diffed. |
| `nodecomp` | The same without decompilation. |
| `js` | `<name>.js` from the extension's `DecompileToJS.java`. |
| `--script` | `<name>.<Probe>.txt` from one of the probes below. |

Every mode also writes `<name>.headless.log`, `<name>.loader.log` and `<name>.analyzer.log`. `summarize.py` totals the metrics, import failures, analyzer errors and JS failures, and lists the samples that differ between two runs.

Probes, for narrowing a problem down:

| Probe | Args | Prints |
| --- | --- | --- |
| `ProbeListing.java` | `<start_hex> <end_hex>` | Code units with labels, bytes, p-code op count and try-region context |
| `ProbeCpool.java` | | Stored constant pool items per function |
| `ProbeContexts.java` | | The scope `ContextTracker` assigns to each context-slot access |
| `ProbeTokens.java` | `<function>` | The decompiler's token tree (`DecompileToJS` input) |

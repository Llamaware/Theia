# Theia

### [CLICK HERE to view the full documentation](https://llamawa.re/Theia/)

## Description

Ghidra plugin to parse, disassemble, and decompile NW.js compiled (.bin) binaries. For Ghidra 12.2.

## Supported NW.js versions:
- v0.29.0 (x86) (node.js version: 9.7.1 / V8 version: 6.5.254.31)

Other versions need a fork, see [docs/FORKING.md](docs/FORKING.md).

## Build instructions

Requires JDK 25 (Ghidra 12.2's minimum).

1.  Clone the repo
2.  `<ghidra>/support/gradle/gradlew buildExtension -PGHIDRA_INSTALL_DIR=<ghidra>` (or set `GHIDRA_INSTALL_DIR`); the zip is written to `dist/`
3.  In Ghidra: File->Install Extensions...->Press green (Plus/+) button, then select the zip. Press OK, then restart Ghidra.
4.  Drag-n-drop .bin files.

For Eclipse/GhidraDev, `scripts/gen_classpath.py <ghidra>` regenerates `.classpath`.

## Usage

- `DecompileToJS` (script category Theia) prints the current function as JavaScript; headless, `-postScript DecompileToJS.java <file>` writes every function.
- Logs are written to `<Ghidra user settings>/Theia/`. Start Ghidra with `-Dtheia.debug=true` for per-instruction analyzer, p-code and constant pool logs.
- `scripts/` holds the fork and test tools, see [scripts/README.md](scripts/README.md).

## Credits

[ghidra_nodejs](https://github.com/PositiveTechnologies/ghidra_nodejs) by @lab313ru (Vladimir Kononovich), @ntlyapova (Natalya Tlyapova), @mavaddat (Mavaddat Javid)

# Theia

## Description

GHIDRA plugin to parse, disassemble, and decompile nwjc (.bin) binaries. For Ghidra v11.3.1.

## Supported nw.js versions:
- v0.29.0 (x86) (node.js version: 9.7.1 / V8 version: 6.5.254.31)

## Build instructions

1.  Clone the repo
2.  Import the repo into Eclipse with GhidraDev plugin installed
3.  Link Ghidra to your Ghidra's installation (option in the project's context menu)
4.  Export & build plugin using the project's context menu. Eclipse will generate a resulting .zip archive with the plugin.
5.  In Ghidra: File->Install Extensions...->Press green (Plus/+) button, then select previously generated .zip archive to install it. Press OK, then Restart Ghidra.
6.  Drag-n-drop .bin files.

## Credits

[ghidra_nodejs](https://github.com/PositiveTechnologies/ghidra_nodejs) by @lab313ru (Vladimir Kononovich), @ntlyapova (Natalya Tlyapova), @mavaddat (Mavaddat Javid)
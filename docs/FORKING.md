# Forking Theia for another NW.js version

Theia targets one V8 build: NW.js 0.29.0 → node 9.7.1 → V8 6.5.254.31, x86. A code cache only loads in the V8 build that wrote it, so a new NW.js version means retargeting Theia at its V8. The tables are generated. Everything else is a diff of V8 headers against the Java and SLEIGH that mirror them.

Prerequisites:

- the V8 `src/` at the matching tag (`process.versions.v8`, or the NW.js release notes);
- a few `.bin` files built with that SDK's `nwjc`, plus their JS;
- a 32-bit target (`V8:LE:32`). 64-bit needs pointer-size work throughout.

## 1. Tables

```
python scripts/gen_data.py <v8>/src data
```

This writes `v8_roots.json`, `v8_builtins.json`, `v8_jsruns.json`, `v8_funcs.json` and `v8_intrinsics.json` in V8 enum order, because Theia indexes them by position.

- **Build flags:** NW.js builds with `V8_INTL_SUPPORT`, which is the default here. Match other build flags with `--define`/`--undef`.
- **Check:** in a loaded sample, the top-level function should call `%DeclareGlobalsForInterpreter`, and throws should call `%Throw`/`%ReThrow`.
- **Renamed macros:** if a list macro was renamed or restructured, fix its function in `gen_data.py`. Each one lists the headers it reads.

## 2. Bytecodes (`data/languages/`)

```
python scripts/remap_opcodes.py <v8>/src --write
python scripts/check_opcodes.py <v8>/src
```

- **New bytecodes:** add constructors for every scale, in `v8.slaspec`, `wide_instructions.sinc` and `extrawide_instructions.sinc`. Keep instruction constructors inside each file's `with : tryBegin=0 { }` block.
- **Iterate:** rerun `check_opcodes.py` until it reports 0 problems. It checks the opcode, the length per scale and the register/number operand order.
- **Recompile:** `<ghidra>/support/sleigh data/languages/v8.slaspec`.

Re-check these semantics against `interpreter/bytecode-generator.cc`, `bytecode-array-accessor.cc` and `interpreter-generator.cc`:

| What | Where |
| --- | --- |
| Register operand encoding (`attach variables`, `a*` = parameters, `r*` = locals) | `v8.slaspec`; parameter storage in `SharedFunctionInfoStruct.initFunction` (`Register::FromParameterIndex`) |
| Jump targets (prefixed forms are relative to the bytecode after the prefix) | `dest`/`destloop`/`w_dest`/`d_dest`; `V8_bytecodeAnalyzer` `prefixOffset` |
| Call operand layout, receiver | `V8_InjectJSCallN`, `V8_InjectCallVariadic`, `V8_InjectCallJSRuntime`, `V8_InjectConstruct` |
| Runtime functions called implicitly (by name) | `V8_InjectThrow.RUNTIME_FUNCTIONS`, `V8_InjectStaDataPropertyInLiteral` |
| Test + jump pairing (`afterTest`), `SwitchOnSmiNoFeedback`, try-region wrapper | `v8.slaspec`; `V8_bytecodeAnalyzer.writeSwitchTables`; `NwjcParser.markTryRegions` |
| Context ops (`Create*Context`, `Push/PopContext`, context slots) | `ContextTracker.step` |
| Operand indices per bytecode | `V8_bytecodeAnalyzer` (`CP_FUNCS`, `CTX_FUNCS`, `JUMP_FUNCS`, ...) |

## 3. Code cache format

Sources: `snapshot/code-serializer.h`, `serializer-common.h`, `deserializer.cc`.

| What | Where |
| --- | --- |
| Magic: `0xC0DE0000 ^ ExternalReferenceTable` size. Read it from a `.bin`'s first dword. | `V8_bytecodeLoader.EXTERNAL_REFERENCE_COUNT` |
| `SerializedCodeData` header (hashes, reservations, code stub keys, payload length) | `NwjcParser.parse` |
| Serializer bytecodes (`kNewObject`, `kBackref`, `kRootArray`, `kHotObject`, raw data, repeats, `kNextChunk`, ...) | `NwjcParser.readData`, `readSpaceData` |
| `SerializerReference` bit fields, large-object/map indices, spaces | `NwjcParser.getBackReferencedObject`, `AllocSpace` |

## 4. Heap object layouts

Mirror these field by field from `objects*.h` (`kXxxOffset`, `DEFINE_FIELD_OFFSET_CONSTANTS`).

| V8 | Theia |
| --- | --- |
| `SharedFunctionInfo` | `SharedFunctionInfoStruct`, including the static `getFunctionLiteralIdOffset` |
| `ScopeInfo`: fields, flag bits, order of the variable parts | `ScopeInfoStruct`, `ScopeInfoFlags` |
| `BytecodeArray`, handler table ranges | `BytecodeStruct`, `HandlerTableStruct` |
| `Script::shared_function_infos` | `NwjcParser.loadSpaceObjects` (pointer slot 12) |
| Strings: sequential, cons, thin, sliced | `ObjectsAllocator.convertString` |
| `FixedArray`, `FixedDoubleArray`, `Tuple2`/`Tuple3` | `ArrayStruct`, `TupleStruct` |
| Literal boilerplates: object = key/value pairs, array = `ConstantElementsPair` | `JsLiterals` |
| `Context` header slots (`MIN_CONTEXT_SLOTS`) | `V8_ConstantPool.CONTEXT_HEADER` |
| `TestTypeOfFlags::LiteralFlag`, `JSRegExp::Flags` | `TypeOfEnum`, `DecompileToJS.regExpFlags` |

## 5. Validate

```
<ghidra>/support/gradle/gradlew buildExtension -PGHIDRA_INSTALL_DIR=<ghidra>
python scripts/harness/run.py <ghidra> dist/<zip> out
python scripts/harness/run.py <ghidra> dist/<zip> out-js --mode js
python scripts/harness/summarize.py out [<previous out>]
```

- **Target:** 0 import failures, 0 error bookmarks and 0 decompile failures. Spot-check the `.js` output against the sources.
- **Deserializer trace:** `loader.log`. The harness copies it per sample; otherwise it is in `<Ghidra user settings>/Theia/`.
- **More logging:** run with `-Dtheia.debug=true` for per-instruction analyzer, p-code and constant-pool logs.
- **Probe scripts:** see `scripts/README.md`.

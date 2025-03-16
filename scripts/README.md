# Scripts

`bytecodes.py` - used to print all V8 bytecodes and generate `new_opcodes.txt`

`rootlist.cpp` - used to generate text file of `roots_` array with types (TODO: some types may be incorrect)

`create_roots_json.py` - used to generate `v8_roots.json` from the roots array text file

`jsrunslist.cpp` - used to generate text file of context slots with types

`create_jsruns_json.py` - used to generate `v8_jsruns.json` from the context slots text file

`builtinslist.cpp` - used to generate text file of builtins

`create_builtins_json.py` - used to generate `v8_builtins.json` from the builtins text file

`jsonprint.py` - print a json file with indexes

`compare-opcodes.py` - compare opcodes used in log files

`parse_slaspec.py` - parse a slaspec and generate `old_opcodes.txt`

`remap_opcodes.py` - use `old_opcodes.txt` and `new_opcodes.txt` to remap `v8.slaspec`, etc. (warning: needs manual correction for functions that no longer exist)

`new_functions.cpp` - generate text file of intrinsic functions

`new_interpreter_intrinsics.cpp` - generate text file of runtime intrinsic functions

`merge_function_json.py` - use `new_functions.txt`, `new_interpreter_intrinsics.txt`, and old `v8_funcs.json` to generate an updated `v8_funcs.json`

`compare_json.py` - find all top-level names in a json that aren't in another json

`json_empty_args.py` - find all names with an empty args array in a json
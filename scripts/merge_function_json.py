import json

# Number of dummy functions to add between the interpreter intrinsics and the rest.
NUM_DUMMY_FUNCTIONS = 0

def load_args_map(existing_json_file):
    """
    Load the existing JSON and return a mapping of function names to their argument lists.
    """
    with open(existing_json_file, 'r') as f:
        existing_data = json.load(f)
    args_map = { entry["Name"]: entry["Args"] for entry in existing_data }
    return args_map

def load_new_functions_from_txt(txt_file):
    """
    Load new functions from the text file produced by the C++ macro expansion.
    Expected format per line: FunctionName:nargs
    """
    new_functions = []
    with open(txt_file, 'r') as f:
        for line in f:
            line = line.strip()
            if not line or ':' not in line:
                continue
            func_name, nargs_str = line.split(':', 1)
            try:
                nargs = int(nargs_str)
            except ValueError:
                nargs = 0
            new_functions.append({
                "Name": func_name,
                "nargs": nargs  # Temporary field; will be used to generate generic args if needed.
            })
    return new_functions

def load_interpreter_intrinsics(intrinsics_txt_file):
    """
    Load the interpreter intrinsics from a text file.
    Expected format per line: kFunctionName:argCount
    """
    intrinsics = []
    with open(intrinsics_txt_file, 'r') as f:
        for line in f:
            line = line.strip()
            if not line or ':' not in line:
                continue
            name, arg_count_str = line.split(':', 1)
            try:
                arg_count = int(arg_count_str)
            except ValueError:
                arg_count = 0
            intrinsics.append({
                "Name": name,
                "nargs": arg_count
            })
    return intrinsics

def update_functions(new_functions, args_map):
    """
    Merge new functions with argument details from the existing JSON.
    For functions not found in the map, generate generic argument names with type 'Unknown'.
    """
    updated_functions = []
    for func in new_functions:
        name = func["Name"]
        nargs = func["nargs"]
        # If name starts with "_", strip it off for lookup in args_map.
        lookup_name = "k" + name[1:] if name.startswith("_") else name
        if lookup_name in args_map:
            args = args_map[lookup_name]
        else:
            # Generate generic arguments: arg1, arg2, ..., argN with type 'Unknown'
            args = [{"Name": f"arg{i+1}", "Type": "Unknown"} for i in range(nargs)]
        updated_functions.append({
            "Name": name,
            "Args": args
        })
    return updated_functions


def generate_dummy_functions(num_dummies):
    """
    Generate a list of dummy function entries.
    """
    dummy_functions = [{
        "Name": f"dummy_function_{i+1}",
        "Args": []
    } for i in range(num_dummies)]
    return dummy_functions

def main():
    # Filenames—adjust as necessary.
    existing_json_file = "v8_funcs.json"           # Existing JSON with complete argument details
    new_functions_txt = "new_functions.txt"          # Output from the C++ macro expansion for intrinsics (non-interpreter)
    interpreter_intrinsics_txt = "new_interpreter_intrinsics.txt"  # Generated by the C++ function
    output_json_file = "new_functions.json"          # Final updated JSON

    # Build a map of function arguments from the existing JSON.
    args_map = load_args_map(existing_json_file)
    
    # Load interpreter intrinsics from file.
    interpreter_intrinsics = load_interpreter_intrinsics(interpreter_intrinsics_txt)
    # Merge interpreter intrinsics with existing argument details.
    interpreter_intrinsics_updated = update_functions(interpreter_intrinsics, args_map)
    
    # Load new functions (the rest of the intrinsics) from the text file.
    new_functions = load_new_functions_from_txt(new_functions_txt)
    updated_functions = update_functions(new_functions, args_map)
    
    # Generate dummy function entries.
    dummy_functions = generate_dummy_functions(NUM_DUMMY_FUNCTIONS)
    
    # Build the final functions list:
    # [interpreter_intrinsics] + [dummy functions] + [the rest of the intrinsics]
    final_functions = interpreter_intrinsics_updated + dummy_functions + updated_functions
    
    # Write out the final updated JSON.
    with open(output_json_file, 'w') as f:
        json.dump(final_functions, f, indent=4)
    
    print(f"New functions JSON generated: {output_json_file}")

if __name__ == "__main__":
    main()

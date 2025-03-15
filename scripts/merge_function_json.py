import json

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

def update_functions(new_functions, args_map):
    """
    Merge new functions with argument details from the existing JSON.
    For functions not found in the map, generate generic argument names with type 'Unknown'.
    """
    updated_functions = []
    for func in new_functions:
        name = func["Name"]
        nargs = func["nargs"]
        if name in args_map:
            args = args_map[name]
        else:
            # Generate generic arguments: arg1, arg2, ..., argN with type 'Unknown'
            args = [{"Name": f"arg{i+1}", "Type": "Unknown"} for i in range(nargs)]
        updated_functions.append({
            "Name": name,
            "Args": args
        })
    return updated_functions

def main():
    # Filenames—adjust as necessary.
    existing_json_file = "v8_funcs.json"       # Existing JSON with complete argument details
    new_functions_txt = "new_functions.txt"      # Output from the C++ macro expansion
    output_json_file = "new_functions.json"      # Final updated JSON
    
    # Build a map of function arguments from the existing JSON.
    args_map = load_args_map(existing_json_file)
    
    # Load new functions from the text file.
    new_functions = load_new_functions_from_txt(new_functions_txt)
    
    # Merge the functions with the existing argument details.
    updated_functions = update_functions(new_functions, args_map)
    
    # Write out the updated JSON.
    with open(output_json_file, 'w') as f:
        json.dump(updated_functions, f, indent=4)
    
    print(f"New functions JSON generated: {output_json_file}")

if __name__ == "__main__":
    main()

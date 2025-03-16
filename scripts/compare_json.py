import json
import sys

def load_names(filename):
    """Load the JSON file and return a set of the top-level 'Name' values."""
    with open(filename, 'r') as f:
        data = json.load(f)
    return {entry["Name"] for entry in data}

def main(file_a, file_b):
    names_a = load_names(file_a)
    names_b = load_names(file_b)
    
    in_a_not_b = names_a - names_b
    in_b_not_a = names_b - names_a

    if in_a_not_b:
        print(f"Names in {file_a} but not in {file_b}:")
        for name in sorted(in_a_not_b):
            print("  " + name)
    else:
        print(f"No names unique to {file_a}.")
    
    print()
    
    if in_b_not_a:
        print(f"Names in {file_b} but not in {file_a}:")
        for name in sorted(in_b_not_a):
            print("  " + name)
    else:
        print(f"No names unique to {file_b}.")

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python compare_json.py fileA.json fileB.json")
        sys.exit(1)
    file_a = sys.argv[1]
    file_b = sys.argv[2]
    main(file_a, file_b)

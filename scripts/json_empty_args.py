import json
import sys

def main(json_file):
    with open(json_file, 'r') as f:
        data = json.load(f)
    
    empty_args_names = [entry["Name"] for entry in data if "Args" in entry and len(entry["Args"]) == 0]
    
    if empty_args_names:
        print("Top-level names with an empty args array:")
        for name in empty_args_names:
            print("  " + name)
    else:
        print("No top-level names with an empty args array were found.")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python json_empty_args.py <json_file>")
        sys.exit(1)
    main(sys.argv[1])

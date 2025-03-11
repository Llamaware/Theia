import json

# Read the list from the file
with open("builtin_list.txt", "r") as file:
    names = [line.strip() for line in file]

# Convert to JSON
json_output = json.dumps(names, indent=4)

# Write to a JSON file
with open("builtin_list.json", "w") as json_file:
    json_file.write(json_output)

print("JSON file created: builtin_list.json")
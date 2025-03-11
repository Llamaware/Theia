import json

# Read input from text file
input_file = "root_indexes.txt"

with open(input_file, "r") as file:
    csv_data = file.read()

# Split CSV into lines
lines = csv_data.splitlines()

# Convert CSV to JSON
json_list = []

for line in lines:
    parts = line.split(", ")
    if len(parts) == 3:
        index, name, type_ = parts
        json_list.append({
            "Name": name,
            "Type": type_.lower()
        })

with open("roots.json", "w") as json_file:
    json_file.write("[\n")
    for i, item in enumerate(json_list):
        json_file.write("    " + json.dumps(item))
        if i < len(json_list) - 1:
            json_file.write(",")
        json_file.write("\n")
    json_file.write("]\n")

print("JSON file created successfully: roots.json")
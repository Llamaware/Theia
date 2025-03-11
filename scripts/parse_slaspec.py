import re

# Path to the .slaspec file
file_path = 'v8.slaspec'

# Regular expression to match opcodes and names
opcode_pattern = re.compile(r'^:(\w+)\s.*op\s*=\s*(0x[0-9a-fA-F]+)')

# List to store the results
opcodes = []

# Read and parse the file
with open(file_path, 'r') as file:
    for line in file:
        match = opcode_pattern.match(line)
        if match:
            name, opcode = match.groups()
            opcodes.append((opcode, name))

# Sort by opcode value
opcodes.sort(key=lambda x: int(x[0], 16))

# Format the output
formatted_output = '\n'.join([f"0x{int(opcode, 16):02X} - {name}" for opcode, name in opcodes])

# Print the result
print(formatted_output)

with open("old_opcodes.txt", "w") as text_file:
    text_file.write(formatted_output)

print("Text file created: old_opcodes.txt")
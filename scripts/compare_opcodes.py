import re

def extract_opcodes(file_path):
    opcodes = set()
    opcode_pattern = re.compile(r'opcode=0x([0-9A-Fa-f]+)')
    
    with open(file_path, 'r') as file:
        for line in file:
            match = opcode_pattern.search(line)
            if match:
                opcodes.add(match.group(1))
    
    return opcodes

def extract_opcodes_from_multiple(files):
    pooled_opcodes = set()
    for file in files:
        pooled_opcodes.update(extract_opcodes(file))
    return pooled_opcodes

def compare_opcodes(reference_file, target_files):
    reference_opcodes = extract_opcodes(reference_file)
    pooled_opcodes = extract_opcodes_from_multiple(target_files)
    
    only_in_reference = reference_opcodes - pooled_opcodes
    only_in_pool = pooled_opcodes - reference_opcodes
    
    print(f"\nOpcodes only in {reference_file}: {only_in_reference}")
    print(f"Opcodes only in pooled target files: {only_in_pool}")

def main():
    reference_file = 'ghidra1.log'  # Update with the reference file name
    target_files = [
        'ghidra2.log', 
        'ghidra3.log',
    ]  # Add all target files here
    
    print(f"Extracting opcodes from {reference_file} and pooling target files...")
    compare_opcodes(reference_file, target_files)

if __name__ == "__main__":
    main()

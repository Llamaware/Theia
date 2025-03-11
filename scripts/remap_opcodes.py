import re

#---------------------------------------------------
# 1) Read old opcodes from a text file
#    Format: "0x0E - PushContext"
#---------------------------------------------------
old_opcodes_file = 'old_opcodes.txt'
old_opcodes_by_name = {}  # { "pushcontext": (0x0E, "PushContext"), ... }

with open(old_opcodes_file, 'r') as f:
    for line in f:
        line = line.strip()
        if not line or '-' not in line:
            continue
        # Example line:  "0x0E - PushContext"
        hex_str, name = [part.strip() for part in line.split('-', maxsplit=1)]
        # hex_str -> "0x0E"
        # name    -> "PushContext"
        old_int = int(hex_str, 16)
        old_opcodes_by_name[name.lower()] = (old_int, name)


#---------------------------------------------------
# 2) Read new opcodes from a text file
#---------------------------------------------------
new_opcodes_file = 'new_opcodes.txt'
new_opcodes_by_name = {}  # { "pushcontext": (0x0D, "PushContext"), ... }

with open(new_opcodes_file, 'r') as f:
    for line in f:
        line = line.strip()
        if not line or '-' not in line:
            continue
        # Example line: "0x0D - PushContext"
        hex_str, name = [part.strip() for part in line.split('-', maxsplit=1)]
        new_int = int(hex_str, 16)
        new_opcodes_by_name[name.lower()] = (new_int, name)


#---------------------------------------------------
# 3) (Optional) Handle known name mismatches or merges
#    E.g.: "StaGlobalSloppy" -> "StaGlobal", "StaGlobalStrict" -> "StaGlobal"
#    Add more rules as needed.
#---------------------------------------------------
rename_map = {
    #"staglobalsloppy": "staglobal",
    #"staglobalstrict": "staglobal",
    #"stanamedpropertysloppy" : "stanamedproperty",
    #"stanamedpropertystrict" : "stanamedproperty",
    #"stakeyedpropertysloppy" : "stakeyedproperty",
    #"stakeyedpropertystrict" : "stakeyedproperty"
    # Add other custom mappings if needed:
    # "popcontext": "popcontext"  # if it changed opcodes, but name is same, no rename needed
}

# We can apply these renames so old_opcodes_by_name has the "new" name key
for old_name_lower in list(old_opcodes_by_name.keys()):
    if old_name_lower in rename_map:
        old_int, old_original_name = old_opcodes_by_name[old_name_lower]
        # rename e.g. "staglobalsloppy" => "staglobal"
        new_lower = rename_map[old_name_lower].lower()
        del old_opcodes_by_name[old_name_lower]  # remove old
        old_opcodes_by_name[new_lower] = (old_int, old_original_name)


#---------------------------------------------------
# 4) Build the mapping {old_opcode_int: new_opcode_int}
#    by matching instruction names (lowercased).
#---------------------------------------------------
opcode_map = {}
for name_lower, (old_int, old_name) in old_opcodes_by_name.items():
    if name_lower in new_opcodes_by_name:
        new_int, new_name = new_opcodes_by_name[name_lower]
        opcode_map[old_int] = new_int

# If you want to see which old instructions have no match:
unmatched = [
    (old_int, old_name) 
    for (k, (old_int, old_name)) in old_opcodes_by_name.items()
    if old_int not in opcode_map
]
if unmatched:
    print("[WARNING] No new opcode found for:")
    for (oi, oname) in unmatched:
        print(f"  0x{oi:X} - {oname}")
    print("You may need to add entries to rename_map or to new_opcodes.txt.")


#---------------------------------------------------
# 5) Regex-substitute in the .slaspec or .sinc file.
#    We'll parse the old opcode as integer, and if in opcode_map, replace.
#---------------------------------------------------
input_slaspec  = 'v8.slaspec'
output_slaspec = 'updated.slaspec'

opcode_pattern = re.compile(r'(op\s*=\s*)(0x[0-9A-Fa-f]+)')

def replace_opcode_func(match):
    prefix = match.group(1)          # "op = "
    old_hex_str = match.group(2)     # e.g. "0x0E"
    old_int_val = int(old_hex_str, 16)
    if old_int_val in opcode_map:
        new_int_val = opcode_map[old_int_val]
        # Convert to hex string.  E.g. "0x0D"
        new_hex_str = f"0x{new_int_val:x}"
        return prefix + new_hex_str
    else:
        return match.group(0)  # No change

with open(input_slaspec, 'r') as fin, open(output_slaspec, 'w') as fout:
    for line in fin:
        new_line = opcode_pattern.sub(replace_opcode_func, line)
        fout.write(new_line)

print(f"[+] Finished updating '{input_slaspec}' → '{output_slaspec}'")

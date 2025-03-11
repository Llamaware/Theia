import json

def parse_context_slots(input_file):
    context_slots = []
    
    # Read the file and parse each line
    with open(input_file, 'r') as file:
        # Skip the first two lines (header lines)
        lines = file.readlines()[2:]
        
        for line in lines:
            # Strip any extra whitespace or newline characters
            line = line.strip()
            
            # Split each line by commas
            parts = line.split(',')
            
            if len(parts) == 3:
                # Extract index, name, and type
                index = int(parts[0].strip())
                name = parts[1].strip()
                type_ = parts[2].strip()
                
                # Add to the context_slots list
                context_slots.append({
                    'Name': name,
                    'Type': type_
                })
    
    return context_slots

def write_json(output_file, context_slots):
    # Write the parsed data to a JSON file
    with open(output_file, 'w') as file:
        json.dump(context_slots, file, indent=4)

def main():
    # Input and output file paths
    input_file = 'context_slots.txt'
    output_file = 'context_slots.json'
    
    # Parse the context slots from the input file
    context_slots = parse_context_slots(input_file)
    
    # Write the parsed context slots to the JSON file
    write_json(output_file, context_slots)
    
    print(f"Context slots have been converted to JSON and saved in {output_file}")

if __name__ == "__main__":
    main()

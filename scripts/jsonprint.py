import json

# Load JSON data from a file
def display_json_entries(file_path):
    try:
        with open(file_path, 'r') as file:
            data = json.load(file)

        # Iterate through the list and print each entry with an index number
        for index, entry in enumerate(data, start=1):
            print(f"{index}: {entry}")
    
    except FileNotFoundError:
        print(f"Error: The file {file_path} does not exist.")
    except json.JSONDecodeError:
        print(f"Error: Failed to decode the JSON from the file.")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")

# Example usage
file_path = 'new_functions.json'  # Replace with your JSON file path
display_json_entries(file_path)

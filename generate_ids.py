import random
import string

def infer_mask(id_list):
    """Infer a character mask from a list of example 16-character IDs."""
    mask = []
    for chars in zip(*id_list):
        if len(set(chars)) == 1:
            mask.append(chars[0])  # Fixed character
        else:
            mask.append('?')       # Variable character
    return ''.join(mask)

def generate_id_from_mask(mask):
    """Generate a pseudo-random ID based on the inferred mask."""
    new_id = ''
    for char in mask:
        if char == '?':
            new_id += random.choice(string.ascii_uppercase + string.digits)
        else:
            new_id += char
    return new_id

def read_ids_from_file(filename):
    """Read valid 16-character IDs from a file."""
    with open(filename, 'r') as file:
        return [line.strip() for line in file if len(line.strip()) == 16]

def generate_ids(mask, count):
    """Generate a specified number of IDs using a given mask."""
    return [generate_id_from_mask(mask) for _ in range(count)]

def main(filename, count=1000, output_file=None):
    id_list = read_ids_from_file(filename)
    if not id_list:
        print("No valid 16-character IDs found.")
        return

    mask = infer_mask(id_list)
    print(f"Inferred Mask: {mask}\n")

    generated_ids = generate_ids(mask, count)

    if output_file:
        with open(output_file, 'w') as f:
            f.write('\n'.join(generated_ids))
        print(f"{count} IDs written to {output_file}")
    else:
        print("Generated IDs:")
        for gid in generated_ids:
            print(gid)

if __name__ == "__main__":
    # You can change these as needed
    main("example_ids.txt", count=1000, output_file="generated_ids.txt")


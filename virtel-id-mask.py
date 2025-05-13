import re
import random
import string

def generate_masked_value(pattern, length=16):
    """
    Generate a string that matches a regex pattern.
    
    Args:
        pattern (str): Regex pattern to match. Static characters will be preserved exactly.
                       For example, "ABC-\d\d\d" will always start with "ABC-" followed by 3 random digits.
        length (int, optional): Length of the output string. Defaults to 16.
    
    Returns:
        str: A randomly generated string that matches the pattern
    """
    if length <= 0:
        raise ValueError("Length must be positive")
    
    # Define character sets for common patterns
    char_sets = {
        r'\d': string.digits,
        r'[0-9]': string.digits,
        r'\w': string.ascii_letters + string.digits + '_',
        r'[a-zA-Z]': string.ascii_letters,
        r'[a-z]': string.ascii_lowercase,
        r'[A-Z]': string.ascii_uppercase,
        r'[a-zA-Z0-9]': string.ascii_letters + string.digits,
        r'.': string.ascii_letters + string.digits + string.punctuation + ' '
    }
    
    result = ""
    position = 0
    
    while len(result) < length:
        # If exact character is specified in pattern
        if position < len(pattern) and pattern[position] not in ('\\', '[', '.', '*', '+', '?', '{', '('):
            result += pattern[position]  # Use static character as-is
            position += 1
            continue
        
        # Handle pattern matching
        matched = False
        for regex, chars in char_sets.items():
            # Check if current position in pattern matches this regex
            if position < len(pattern) and re.match(f"^{regex}", pattern[position:]):
                result += random.choice(chars)
                # Move position by the length of the regex pattern
                position += len(regex)
                matched = True
                break
        
        # If no pattern matched or we reached the end of pattern, use alphanumeric
        if not matched:
            result += random.choice(string.ascii_letters + string.digits)
            # If we have a pattern but reached its end, reset to beginning for repeating patterns
            if position >= len(pattern) and len(pattern) > 0:
                position = 0
            # Otherwise just advance position if there are more characters
            elif position < len(pattern):
                position += 1
    
    return result[:length]

# Examples
if __name__ == "__main__":
    # Example with static values "PREFIX-" and "-SUFFIX" with random characters in between
    print(generate_masked_value(r'PREFIX-\d\d\d\d-[A-Z][A-Z]-SUFFIX', 24))
    
    # Generate a product key with fixed format and static separator
    print(generate_masked_value(r'WS2025-[A-Z0-9][A-Z0-9][A-Z0-9][A-Z0-9]-[A-Z0-9][A-Z0-9][A-Z0-9][A-Z0-9]'))
    
    # Credit card style number with static first digits (e.g., 4 for Visa)
    print(generate_masked_value(r'4\d\d\d-\d\d\d\d-\d\d\d\d-\d\d\d\d', 19))
    
    # Generate an alphanumeric string
    print(generate_masked_value(r'[a-zA-Z0-9]'))

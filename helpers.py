from string import ascii_uppercase, ascii_lowercase, digits

def pattern_gen(length):
    pattern = ""
    for upper in ascii_uppercase:
        for lower in ascii_lowercase:
            for digit in digits:
                if len(pattern) < length:
                    pattern += upper + lower + digit
                else:
                    out = pattern[:length]
                    return out

    return pattern[:length]

def pattern_search(search_pattern):
    needle = search_pattern
    try:
        if needle.startswith("0x"):
            needle = needle[2:]
            needle = bytearray.fromhex(needle).decode("ascii")
            needle = needle[::-1]
    except (ValueError, TypeError) as e:
        raise

    haystack = ""
    for upper in ascii_uppercase:
        for lower in ascii_lowercase:
            for digit in digits:
                haystack += upper + lower + digit
                found_at = haystack.find(needle)
                if found_at > -1:
                    return found_at

def return_pretty_hex(data):
    prettier = ""
    for char in data:
        is_missing = False
        if type(char) != int:
            char = ord(char)
        if char < 16:
            is_missing = True
        char = hex(char)
        char = char[1:]
        if is_missing:
            char = char[0] + '0' + char[1:] 
        prettier += '\\' + str(char)

    return prettier
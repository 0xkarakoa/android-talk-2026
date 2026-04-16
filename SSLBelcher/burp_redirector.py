import argparse
import subprocess


class SSLBelcher:
    def __init__(self, device=None, burp_ip="192.168.1.100", burp_port=8080, chain="BURP"):
        self.device = device
        self.burp_ip = burp_ip
        self.burp_port = burp_port
        self.chain = chain

    # ----------------------------
    # ADB wrapper
    # ----------------------------
    def _adb(self, cmd: str):
        base = ["adb"]

        if self.device:
            base += ["-s", self.device]

        base += ["shell", "su", "-c", cmd]

        return subprocess.run(base, capture_output=True, text=True)

    # ----------------------------
    # Frida handling
    # ----------------------------
    def frida_check(self):
        result = self._adb("pidof frida-server || true")
        return result.stdout.strip()

    def frida_start(self):
        print("[*] Checking Frida server...")

        pid = self.frida_check()
        if pid:
            print(f"[+] Frida already running (PID: {pid})")
            return

        print("[*] Starting Frida server...")

        cmd = (
            "chmod 755 /data/local/tmp/frida-server && "
            "nohup /data/local/tmp/frida-server >/dev/null 2>&1 &"
        )

        self._adb(cmd)

        pid = self.frida_check()
        if pid:
            print(f"[+] Frida started (PID: {pid})")
        else:
            print("[-] Failed to start Frida server (check binary/arch/permissions)")

    def frida_status(self):
        pid = self.frida_check()
        if pid:
            print(f"[+] Frida running (PID: {pid})")
        else:
            print("[-] Frida NOT running")

    # ----------------------------
    # iptables enable
    # ----------------------------
    def enable(self):
        print("[*] Enabling SSLBelcher...")

        # ensure Frida is up first
        self.frida_start()

        cmds = [
            # create chain safely
            f"iptables -t nat -N {self.chain} 2>/dev/null || true",

            # attach chain to OUTPUT safely
            f"iptables -t nat -D OUTPUT -j {self.chain} 2>/dev/null || true",
            f"iptables -t nat -A OUTPUT -j {self.chain}",

            # avoid looping back into burp
            f"iptables -t nat -A {self.chain} -d {self.burp_ip} -j RETURN",

            # redirect HTTP/HTTPS
            f"iptables -t nat -A {self.chain} -p tcp --dport 80 -j DNAT --to-destination {self.burp_ip}:{self.burp_port}",
            f"iptables -t nat -A {self.chain} -p tcp --dport 443 -j DNAT --to-destination {self.burp_ip}:{self.burp_port}",
        ]

        for c in cmds:
            self._adb(c)

        print("[+] SSLBelcher ENABLED (Frida + Burp ready)")

    # ----------------------------
    # disable cleanly
    # ----------------------------
    def disable(self):
        print("[*] Disabling SSLBelcher...")

        cmds = [
            f"iptables -t nat -D OUTPUT -j {self.chain} 2>/dev/null || true",
            f"iptables -t nat -F {self.chain} 2>/dev/null || true",
            f"iptables -t nat -X {self.chain} 2>/dev/null || true",
        ]

        for c in cmds:
            self._adb(c)

        print("[-] SSLBelcher DISABLED")

    # ----------------------------
    # status output
    # ----------------------------
    def status(self):
        print("\n[*] === IPTABLES NAT TABLE ===")
        result = self._adb("iptables -t nat -L -n -v --line-numbers")
        print(result.stdout)

        print("[*] === FRIDA STATUS ===")
        self.frida_status()


# ----------------------------
# CLI ENTRYPOINT
# ----------------------------
def main():
    parser = argparse.ArgumentParser(description="SSLBelcher - ADB Mobile Interception Controller")

    parser.add_argument("command", choices=["enable", "disable", "status", "frida"])
    parser.add_argument("--ip", default="192.168.1.100", help="Burp IP")
    parser.add_argument("--port", type=int, default=8080, help="Burp port")
    parser.add_argument("--device", default=None, help="ADB device ID")

    args = parser.parse_args()

    tool = SSLBelcher(
        device=args.device,
        burp_ip=args.ip,
        burp_port=args.port
    )

    if args.command == "enable":
        tool.enable()

    elif args.command == "disable":
        tool.disable()

    elif args.command == "status":
        tool.status()

    elif args.command == "frida":
        tool.frida_status()


if __name__ == "__main__":
    main()
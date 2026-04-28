import subprocess


class IPTablesBlocker:
    def __init__(self, protected_ips=None):
        self.protected_ips = set(protected_ips or [])

    def is_protected(self, ip: str) -> bool:
        if not ip:
            return True
        if ip in self.protected_ips:
            return True
        if ip.startswith("10."):
            return True
        if ip.startswith("192.168."):
            return True

        # Protect the full private 172.16.0.0/12 range, including AWS 172.31.x.x
        try:
            parts = ip.split(".")
            if len(parts) == 4:
                first = int(parts[0])
                second = int(parts[1])
                if first == 172 and 16 <= second <= 31:
                    return True
        except Exception:
            return True

        return False

    def _rule_exists(self, chain: str, ip: str) -> bool:
        result = subprocess.run(
            ["iptables", "-C", chain, "-s", ip, "-j", "DROP"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        return result.returncode == 0

    def _insert_rule(self, chain: str, ip: str) -> bool:
        if self._rule_exists(chain, ip):
            return True

        result = subprocess.run(
            ["iptables", "-I", chain, "1", "-s", ip, "-j", "DROP"],
            capture_output=True,
            text=True,
        )

        if result.returncode != 0:
            print(f"[IPTABLES-{chain}-ERROR] {result.stderr}", flush=True)
            return False

        return True

    def block(self, ip: str) -> bool:
        if self.is_protected(ip):
            print(f"[IPTABLES-SKIP] Protected/private IP not blocked: {ip}", flush=True)
            return False

        input_ok = self._insert_rule("INPUT", ip)

        # Docker-published ports often pass through FORWARD/DOCKER-USER.
        # This makes the block effective for container traffic too.
        docker_user_ok = True
        chains = subprocess.run(
            ["iptables", "-S"],
            capture_output=True,
            text=True,
        )

        if "DOCKER-USER" in chains.stdout:
            docker_user_ok = self._insert_rule("DOCKER-USER", ip)

        return input_ok or docker_user_ok

    def unblock(self, ip: str) -> bool:
        for chain in ["INPUT", "DOCKER-USER"]:
            while True:
                result = subprocess.run(
                    ["iptables", "-D", chain, "-s", ip, "-j", "DROP"],
                    capture_output=True,
                    text=True,
                )

                if result.returncode != 0:
                    break

        return True

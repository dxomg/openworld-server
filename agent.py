import subprocess
import json
import os
import time
import re
import toml
from datetime import datetime

CONFIG_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "config.toml")

DEFAULT_THRESHOLDS = {
    "cpu_max_percent": 90,
    "cpu_sustained_seconds": 120,
    "ram_max_percent": 95,
    "disk_max_gb": 0,
    "diskio_max_mbps": 200,
    "net_max_mbps": 500,
    "check_interval": 30,
    "ban_duration_minutes": 30,
    "max_violations_before_ban": 3,
}

MINING_PATTERNS = [
    r"xmrig",
    r"minerd",
    r"cpuminer",
    r"cgminer",
    r"bfgminer",
    r"ethminer",
    r"nbminer",
    r"t-rex",
    r"gminer",
    r"lolminer",
    r"phoenixminer",
    r"nanominer",
    r"cryptonight",
    r"stratum\+tcp",
    r"stratum\+ssl",
    r"pool\.minexmr",
    r"pool\.supportxmr",
    r"xmr\.pool",
    r"monerohash",
    r"hashrate",
]

MINING_REGEX = re.compile("|".join(MINING_PATTERNS), re.IGNORECASE)

class AbuseAgent:
    def __init__(self):
        self.config = self._loadconfig()
        self.thresholds = {**DEFAULT_THRESHOLDS, **self.config.get("abuse", {})}
        self.violations = {}
        self.banned = {}

    def _loadconfig(self):
        if not os.path.exists(CONFIG_PATH):
            return {}
        try:
            return toml.load(CONFIG_PATH)
        except Exception:
            return {}

    def _log(self, level, msg):
        ts = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
        print(f"[{ts}] [{level.upper()}] {msg}")

    def _run(self, cmd, timeout=10):
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            return r.returncode, r.stdout.strip(), r.stderr.strip()
        except subprocess.TimeoutExpired:
            return 1, "", "timeout"
        except FileNotFoundError:
            return 1, "", "docker not found"

    def getcontainers(self):
        code, out, _ = self._run(["docker", "ps", "-a", "--format",
            '{"id":"{{.ID}}","name":"{{.Names}}","status":"{{.Status}}","state":"{{.State}}"}'])
        if code != 0:
            return []
        containers = []
        for line in out.splitlines():
            try:
                containers.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        return containers

    def getstats(self, name):
        code, out, _ = self._run(["docker", "stats", name, "--no-stream", "--format",
            '{"cpu":"{{.CPUPerc}}","mem":"{{.MemPerc}}","mem_usage":"{{.MemUsage}}","net":"{{.NetIO}}","block":"{{.BlockIO}}"}'])
        if code != 0:
            return None
        try:
            return json.loads(out)
        except json.JSONDecodeError:
            return None

    def getdiskusage(self, name):
        code, out, _ = self._run(["docker", "exec", name, "df", "-B1", "/"])
        if code != 0:
            return None
        lines = out.splitlines()
        if len(lines) < 2:
            return None
        parts = lines[1].split()
        if len(parts) < 3:
            return None
        try:
            total = int(parts[1])
            used = int(parts[2])
            return {"total": total, "used": used, "totalGb": round(total / (1024**3), 2), "usedGb": round(used / (1024**3), 2)}
        except (ValueError, IndexError):
            return None

    def checkmining(self, name):
        checks = [
            ["docker", "exec", name, "pgrep", "-af", "miner"],
            ["docker", "exec", name, "pgrep", "-af", "xmrig"],
            ["docker", "exec", name, "pgrep", "-af", "stratum"],
        ]
        for cmd in checks:
            code, out, _ = self._run(cmd, timeout=5)
            if code == 0 and out:
                for line in out.splitlines():
                    if MINING_REGEX.search(line):
                        return line
        code, out, _ = self._run(["docker", "exec", name, "ps", "aux"], timeout=5)
        if code == 0:
            for line in out.splitlines():
                if MINING_REGEX.search(line):
                    return line
        return None

    def checknetworkconnections(self, name):
        code, out, _ = self._run(["docker", "exec", name, "ss", "-tunp"], timeout=5)
        if code != 0:
            return []
        suspicious = []
        mining_ports = [3333, 4444, 5555, 7777, 8888, 9999, 14433, 14444, 45560, 45700]
        for line in out.splitlines():
            parts = line.split()
            if len(parts) < 5:
                continue
            remote = parts[4] if len(parts) > 4 else ""
            for port in mining_ports:
                if f":{port}" in remote:
                    suspicious.append(line.strip())
                    break
        return suspicious

    def suspendcontainer(self, name, reason):
        self._run(["docker", "stop", "-t", "5", name])
        self._log("warn", f"SUSPENDED container '{name}': {reason}")

    def unsuspendcontainer(self, name):
        self._run(["docker", "start", name])
        self._log("info", f"UNSUSPENDED container '{name}'")

    def addviolation(self, name, vtype, detail):
        if name not in self.violations:
            self.violations[name] = []
        self.violations[name].append({
            "type": vtype,
            "detail": detail,
            "time": datetime.utcnow().isoformat(),
        })
        self._log("warn", f"VIOLATION [{vtype}] container '{name}': {detail}")

        maxv = self.thresholds["max_violations_before_ban"]
        if len(self.violations[name]) >= maxv:
            self.suspendcontainer(name, f"exceeded {maxv} violations")
            self.banned[name] = {
                "until": time.time() + self.thresholds["ban_duration_minutes"] * 60,
                "reason": f"exceeded {maxv} violations",
            }
            self.violations[name] = []

    def _parsebytes(self, s):
        """Parse a byte string like '1.5MiB' or '100KB' to MB."""
        s = s.strip()
        match = re.match(r"(\d+\.?\d*)\s*([A-Za-z]+)", s)
        if not match:
            return 0
        val = float(match.group(1))
        unit = match.group(2).upper()
        multipliers = {"B": 1/1024/1024, "KB": 1/1024, "KIB": 1/1024, "MB": 1, "MIB": 1,
                       "GB": 1024, "GIB": 1024, "TB": 1024*1024, "TIB": 1024*1024}
        return val * multipliers.get(unit, 1)

    def checkcontainer(self, container):
        name = container["name"]
        state = container.get("state", "")

        if name in self.banned:
            if time.time() > self.banned[name]["until"]:
                self.unsuspendcontainer(name)
                del self.banned[name]
            else:
                return

        if state != "running":
            return

        stats = self.getstats(name)
        if not stats:
            return

        cpu_str = stats.get("cpu", "0%").replace("%", "").strip()
        mem_str = stats.get("mem", "0%").replace("%", "").strip()
        net_str = stats.get("net", "0B / 0B").strip()

        try:
            cpu = float(cpu_str)
        except ValueError:
            cpu = 0
        try:
            mem = float(mem_str)
        except ValueError:
            mem = 0

        if cpu > self.thresholds["cpu_max_percent"]:
            self.addviolation(name, "cpu", f"CPU at {cpu:.1f}%")

        if mem > self.thresholds["ram_max_percent"]:
            self.addviolation(name, "ram", f"RAM at {mem:.1f}%")

        disk = self.getdiskusage(name)
        if disk and self.thresholds["disk_max_gb"] > 0:
            if disk["usedGb"] > self.thresholds["disk_max_gb"]:
                self.addviolation(name, "disk", f"Disk at {disk['usedGb']}GB (limit {self.thresholds['disk_max_gb']}GB)")

        block_str = stats.get("block", "0B / 0B").strip()
        block_parts = block_str.split(" / ")
        if len(block_parts) == 2:
            block_read = self._parsebytes(block_parts[0])
            block_write = self._parsebytes(block_parts[1])
            block_total = block_read + block_write
            if self.thresholds["diskio_max_mbps"] > 0 and block_total > self.thresholds["diskio_max_mbps"]:
                self.addviolation(name, "diskio", f"Disk I/O at {block_total:.0f}MB (read {block_read:.0f}MB + write {block_write:.0f}MB)")

        net_match = re.search(r"(\d+\.?\d*)\s*([A-Za-z]+)", net_str)
        if net_match:
            net_val = float(net_match.group(1))
            net_unit = net_match.group(2).upper()
            if "G" in net_unit:
                net_val *= 1000
            if net_val > self.thresholds["net_max_mbps"]:
                self.addviolation(name, "network", f"Network I/O at {net_val:.0f}MB")

        mining = self.checkmining(name)
        if mining:
            self.addviolation(name, "mining", f"Mining process detected: {mining[:100]}")
            self.suspendcontainer(name, "mining detected")
            self.banned[name] = {
                "until": time.time() + self.thresholds["ban_duration_minutes"] * 60 * 10,
                "reason": "mining detected",
            }

        suspicious = self.checknetworkconnections(name)
        if suspicious:
            self.addviolation(name, "network", f"Suspicious connections: {len(suspicious)} mining-pool ports")

    def runonce(self):
        containers = self.getcontainers()
        self._log("info", f"Scanning {len(containers)} containers...")
        for c in containers:
            try:
                self.checkcontainer(c)
            except Exception as e:
                self._log("error", f"Error checking {c.get('name', '?')}: {e}")

    def runloop(self):
        interval = self.thresholds["check_interval"]
        self._log("info", f"Abuse agent started (interval={interval}s)")
        while True:
            try:
                self.runonce()
            except KeyboardInterrupt:
                self._log("info", "Shutting down")
                break
            except Exception as e:
                self._log("error", f"Agent loop error: {e}")
            time.sleep(interval)


if __name__ == "__main__":
    agent = AbuseAgent()
    agent.runloop()

from flask import Flask, jsonify, request
import os, re, secrets, subprocess, string, json, shutil, toml
from functools import wraps
from datetime import datetime

VERSION = "v1"
CONFIG_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "config.toml")
SAFE_PARAM_RE = re.compile(r"^[A-Za-z0-9_\-\./:]{1,128}$")

DEFAULT_CONFIG = {
    "server": {"host": "0.0.0.0", "port": 1234, "debug": False},
    "auth": {"api_key": f"key_{secrets.token_urlsafe(32)}"},
    "storage": {"base_path": "/var/lib/openworld/disks"},
    "abuse": {
        "cpu_max_percent": 90,
        "ram_max_percent": 95,
        "disk_max_gb": 0,
        "net_max_mbps": 500,
        "check_interval": 30,
        "ban_duration_minutes": 30,
        "max_violations_before_ban": 3,
    },
}

LXCFS_MOUNTS = [
    "/var/lib/lxcfs/proc/cpuinfo:/proc/cpuinfo:rw",
    "/var/lib/lxcfs/proc/meminfo:/proc/meminfo:rw",
    "/var/lib/lxcfs/proc/stat:/proc/stat:rw",
    "/var/lib/lxcfs/proc/swaps:/proc/swaps:rw",
    "/var/lib/lxcfs/proc/uptime:/proc/uptime:rw",
]

def loadconfig():
    if not os.path.exists(CONFIG_PATH):
        with open(CONFIG_PATH, "w") as f:
            toml.dump(DEFAULT_CONFIG, f)
        return DEFAULT_CONFIG
    return toml.load(CONFIG_PATH)

config = loadconfig()

def requireapikey(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        key = request.headers.get("X-API-Key", "")
        if not key or not secrets.compare_digest(key, config["auth"]["api_key"]):
            return jsonify({"error": "unauthorized"}), 401
        return fn(*args, **kwargs)
    return wrapper

def validatesafeparams(params):
    for key, value in params.items():
        if value is None:
            continue
        if not SAFE_PARAM_RE.match(str(value)):
            return False, key
    return True, None

def parsedockerstats(raw):
    """Parse docker stats JSON into clean metrics."""
    try:
        data = json.loads(raw)
    except (json.JSONDecodeError, TypeError):
        return None

    if not data:
        return None

    stats = data[0] if isinstance(data, list) else data

    cpu = stats.get("CPUPerc", "0%").strip()
    mem = stats.get("MemUsage", "0B / 0B").strip()
    net = stats.get("NetIO", "0B / 0B").strip()
    block = stats.get("BlockIO", "0B / 0B").strip()

    mem_parts = mem.split(" / ")
    memusage = mem_parts[0].strip() if len(mem_parts) > 0 else "0B"
    memlimit = mem_parts[1].strip() if len(mem_parts) > 1 else "0B"

    net_parts = net.split(" / ")
    netin = net_parts[0].strip() if len(net_parts) > 0 else "0B"
    netout = net_parts[1].strip() if len(net_parts) > 1 else "0B"

    return {
        "cpu": cpu,
        "memoryUsage": memusage,
        "memoryLimit": memlimit,
        "netIn": netin,
        "netOut": netout,
        "blockIn": block.split(" / ")[0].strip() if " / " in block else block,
        "blockOut": block.split(" / ")[1].strip() if " / " in block else "0B",
    }

# --- Docker Operations ---

def dockerexec(cmd, timeout=30):
    """Run a docker command and return (returncode, stdout, stderr)."""
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return result.returncode, result.stdout.strip(), result.stderr.strip()
    except subprocess.TimeoutExpired:
        return 1, "", "command timed out"
    except FileNotFoundError:
        return 1, "", "docker not found"

def containerexists(name):
    code, out, _ = dockerexec(["docker", "inspect", "--format", "{{.State.Status}}", name])
    return code == 0, out if code == 0 else None

def containerstatus(name):
    code, out, _ = dockerexec(["docker", "inspect", "--format", "{{.State.Status}}", name])
    if code != 0:
        return "offline"
    return out

def dockercreatevps(uuid, hostname, cpu, ram, swap, network, ip, dns, image, rootpassword):
    hostdatadir = os.path.join(config["storage"]["base_path"], uuid)
    os.makedirs(hostdatadir, exist_ok=True)

    cmd = [
        "docker", "create",
        "--runtime=sysbox-runc",
        "--name", hostname,
        "--hostname", hostname,
        "--network", network,
        f"--ip={ip}" if ":" not in ip else f"--ip6={ip}",
        "--cpus", str(cpu),
        "--memory", ram,
        "--memory-swap", swap,
        "-e", f"ROOT_PASSWORD={rootpassword}",
        "-v", f"{hostdatadir}:/data",
    ]

    if isinstance(dns, list):
        for server in dns:
            cmd += ["--dns", server]
    elif dns:
        cmd += ["--dns", str(dns)]

    for mount in LXCFS_MOUNTS:
        cmd += ["-v", mount]

    cmd.append(image)

    code, out, err = dockerexec(cmd, timeout=120)
    if code != 0:
        raise RuntimeError(err or "container creation failed")
    return out

def dockerdestroyvps(hostname, uuid):
    dockerexec(["docker", "rm", "-f", hostname])
    dirpath = os.path.join(config["storage"]["base_path"], uuid)
    if os.path.exists(dirpath):
        shutil.rmtree(dirpath)
    return True

def dockerstartvps(hostname):
    code, out, err = dockerexec(["docker", "start", hostname])
    if code != 0:
        raise RuntimeError(err or "start failed")
    return "running"

def dockerstopvps(hostname):
    code, out, err = dockerexec(["docker", "stop", "-t", "10", hostname])
    if code != 0:
        raise RuntimeError(err or "stop failed")
    return "stopped"

def dockerrestartvps(hostname):
    code, out, err = dockerexec(["docker", "restart", "-t", "10", hostname])
    if code != 0:
        raise RuntimeError(err or "restart failed")
    return "running"

def dockerstatsvps(hostname):
    code, out, err = dockerexec(["docker", "stats", hostname, "--no-stream", "--format",
        '{"CPUPerc":"{{.CPUPerc}}","MemUsage":"{{.MemUsage}}","NetIO":"{{.NetIO}}","BlockIO":"{{.BlockIO}}"}'])
    if code != 0:
        return None
    return parsedockerstats(out)

def dockerinspectvps(hostname):
    code, out, err = dockerexec(["docker", "inspect", hostname])
    if code != 0:
        return None
    try:
        data = json.loads(out)
        return data[0] if isinstance(data, list) and data else data
    except (json.JSONDecodeError, TypeError):
        return None

# --- Routes ---

app = Flask(__name__)
API = f"/api/{VERSION}"

@app.route(f"{API}/health", methods=["GET"])
def health():
    return jsonify({"status": "ok", "version": VERSION, "time": datetime.utcnow().isoformat()})

# --- VPS CRUD ---

@app.route(f"{API}/vps", methods=["POST"])
@requireapikey
def createvps():
    data = request.json
    if not data:
        return jsonify({"error": "json body required"}), 400

    required = ["uuid", "hostname", "cpu", "ram", "swap", "network", "ip", "dns", "image", "rootPassword"]
    missing = [k for k in required if k not in data]
    if missing:
        return jsonify({"error": f"missing fields: {', '.join(missing)}"}), 400

    ok, badkey = validatesafeparams({
        "uuid": data["uuid"],
        "hostname": data["hostname"],
        "network": data["network"],
        "ip": data["ip"],
        "image": data["image"],
    })
    if not ok:
        return jsonify({"error": f"invalid parameter: {badkey}"}), 400

    exists, _ = containerexists(data["hostname"])
    if exists:
        return jsonify({"error": "container already exists"}), 409

    try:
        containerid = dockercreatevps(
            uuid=data["uuid"],
            hostname=data["hostname"],
            cpu=data["cpu"],
            ram=data["ram"],
            swap=data["swap"],
            network=data["network"],
            ip=data["ip"],
            dns=data["dns"],
            image=data["image"],
            rootpassword=data["rootPassword"],
        )
        return jsonify({"containerId": containerid, "hostname": data["hostname"], "status": "created"}), 201
    except RuntimeError as e:
        return jsonify({"error": str(e)}), 500

@app.route(f"{API}/vps/<hostname>", methods=["DELETE"])
@requireapikey
def destroyvps(hostname):
    ok, badkey = validatesafeparams({"hostname": hostname})
    if not ok:
        return jsonify({"error": "invalid hostname"}), 400

    uuid = request.args.get("uuid", "")
    if not uuid:
        return jsonify({"error": "uuid query param required"}), 400

    dockerdestroyvps(hostname, uuid)
    return jsonify({"hostname": hostname, "status": "destroyed"})

# --- VPS Actions ---

@app.route(f"{API}/vps/<hostname>/start", methods=["POST"])
@requireapikey
def startvps(hostname):
    ok, _ = validatesafeparams({"hostname": hostname})
    if not ok:
        return jsonify({"error": "invalid hostname"}), 400

    exists, _ = containerexists(hostname)
    if not exists:
        return jsonify({"error": "container not found"}), 404

    try:
        status = dockerstartvps(hostname)
        return jsonify({"hostname": hostname, "status": status})
    except RuntimeError as e:
        return jsonify({"error": str(e)}), 500

@app.route(f"{API}/vps/<hostname>/stop", methods=["POST"])
@requireapikey
def stopvps(hostname):
    ok, _ = validatesafeparams({"hostname": hostname})
    if not ok:
        return jsonify({"error": "invalid hostname"}), 400

    exists, _ = containerexists(hostname)
    if not exists:
        return jsonify({"error": "container not found"}), 404

    try:
        status = dockerstopvps(hostname)
        return jsonify({"hostname": hostname, "status": status})
    except RuntimeError as e:
        return jsonify({"error": str(e)}), 500

@app.route(f"{API}/vps/<hostname>/restart", methods=["POST"])
@requireapikey
def restartvps(hostname):
    ok, _ = validatesafeparams({"hostname": hostname})
    if not ok:
        return jsonify({"error": "invalid hostname"}), 400

    exists, _ = containerexists(hostname)
    if not exists:
        return jsonify({"error": "container not found"}), 404

    try:
        status = dockerrestartvps(hostname)
        return jsonify({"hostname": hostname, "status": status})
    except RuntimeError as e:
        return jsonify({"error": str(e)}), 500

# --- VPS Status & Metrics ---

@app.route(f"{API}/vps/<hostname>/status", methods=["GET"])
@requireapikey
def vpsstatus(hostname):
    ok, _ = validatesafeparams({"hostname": hostname})
    if not ok:
        return jsonify({"error": "invalid hostname"}), 400

    status = containerstatus(hostname)
    info = dockerinspectvps(hostname)

    result = {"hostname": hostname, "status": status}

    if info:
        state = info.get("State", {})
        result["running"] = state.get("Running", False)
        result["pid"] = state.get("Pid", 0)
        result["startedAt"] = state.get("StartedAt", "")
        result["finishedAt"] = state.get("FinishedAt", "")

        networksettings = info.get("NetworkSettings", {})
        ips = {}
        for netname, netdata in networksettings.get("Networks", {}).items():
            if netdata.get("IPAddress"):
                ips[netname] = netdata["IPAddress"]
            if netdata.get("GlobalIPv6Address"):
                ips[netname + "_ipv6"] = netdata["GlobalIPv6Address"]
        if ips:
            result["ips"] = ips

    return jsonify(result)

@app.route(f"{API}/vps/<hostname>/stats", methods=["GET"])
@requireapikey
def vpsstats(hostname):
    ok, _ = validatesafeparams({"hostname": hostname})
    if not ok:
        return jsonify({"error": "invalid hostname"}), 400

    status = containerstatus(hostname)
    if status != "running":
        return jsonify({"hostname": hostname, "status": status, "metrics": None})

    metrics = dockerstatsvps(hostname)
    return jsonify({"hostname": hostname, "status": status, "metrics": metrics})

# --- Legacy Compat ---

@app.route(f"{API}/dockercreatevps", methods=["POST"])
@requireapikey
def legacycreate():
    return createvps()

@app.route(f"{API}/vps_action", methods=["POST"])
@requireapikey
def legacyaction():
    data = request.json
    if not data:
        return jsonify({"error": "json body required"}), 400
    hostname = data.get("hostname") or data.get("container_id")
    action = data.get("action")
    if not hostname or not action:
        return jsonify({"error": "hostname and action required"}), 400
    if action == "start":
        return startvps(hostname)
    elif action == "stop":
        return stopvps(hostname)
    elif action == "restart":
        return restartvps(hostname)
    return jsonify({"error": "invalid action"}), 400

@app.route(f"{API}/dockerstatsvps", methods=["GET"])
@requireapikey
def legacystats():
    hostname = request.args.get("container_id") or request.args.get("hostname")
    if not hostname:
        return jsonify({"error": "hostname param required"}), 400
    return vpsstats(hostname)

# --- Abuse Detection ---

_abuseagent = None

def getabuseagent():
    global _abuseagent
    if _abuseagent is None:
        from agent import AbuseAgent
        _abuseagent = AbuseAgent()
    return _abuseagent

@app.route(f"{API}/abuse/scan", methods=["POST"])
@requireapikey
def abusescan():
    """Run an immediate abuse scan on all containers."""
    agent = getabuseagent()
    agent.runonce()
    return jsonify({"status": "scan complete", "violations": agent.violations, "banned": {k: {"until": v["until"], "reason": v["reason"]} for k, v in agent.banned.items()}})

@app.route(f"{API}/abuse/violations", methods=["GET"])
@requireapikey
def abuseviolations():
    """Get current violations and banned containers."""
    agent = getabuseagent()
    return jsonify({
        "violations": agent.violations,
        "banned": {k: {"until": v["until"], "reason": v["reason"]} for k, v in agent.banned.items()},
    })

@app.route(f"{API}/abuse/unsuspend/<hostname>", methods=["POST"])
@requireapikey
def abuseunsuspend(hostname):
    """Manually unsuspend a container."""
    ok, _ = validatesafeparams({"hostname": hostname})
    if not ok:
        return jsonify({"error": "invalid hostname"}), 400

    agent = getabuseagent()
    if hostname in agent.banned:
        del agent.banned[hostname]
    if hostname in agent.violations:
        del agent.violations[hostname]
    agent.unsuspendcontainer(hostname)
    return jsonify({"hostname": hostname, "status": "unsuspended"})

@app.route(f"{API}/abuse/config", methods=["GET"])
@requireapikey
def abuseconfig():
    """Get current abuse thresholds."""
    agent = getabuseagent()
    return jsonify(agent.thresholds)

@app.route(f"{API}/abuse/config", methods=["POST"])
@requireapikey
def abuseconfigupdate():
    """Update abuse thresholds."""
    data = request.json
    if not data:
        return jsonify({"error": "json body required"}), 400
    agent = getabuseagent()
    for k, v in data.items():
        if k in agent.thresholds:
            agent.thresholds[k] = v
    return jsonify(agent.thresholds)

@app.errorhandler(404)
def notfound(e):
    return jsonify({"error": "not found"}), 404

@app.errorhandler(405)
def methodnotallowed(e):
    return jsonify({"error": "method not allowed"}), 405

if __name__ == "__main__":
    app.run(host=config["server"]["host"], port=config["server"]["port"])

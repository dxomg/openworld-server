from flask import Flask, jsonify, request
import os, re, secrets, subprocess, string, json, shutil, toml
from functools import wraps

VERSION = "v1"
CONFIG_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "config.toml")
SAFE_PARAM_RE = re.compile(r"^[A-Za-z0-9_\-\./:]{1,128}$")

DEFAULT_CONFIG = {
    "server": {"host": "0.0.0.0", "port": 1234, "debug": False},
    "auth": {"api_key": f"key_{secrets.token_urlsafe(32)}"},
    "storage": {"base_path": "/var/lib/openworld/disks"}
}

LXCFS_MOUNTS = [
    "/var/lib/lxcfs/proc/cpuinfo:/proc/cpuinfo:rw",
    "/var/lib/lxcfs/proc/meminfo:/proc/meminfo:rw",
    "/var/lib/lxcfs/proc/stat:/proc/stat:rw",
    "/var/lib/lxcfs/proc/swaps:/proc/swaps:rw",
    "/var/lib/lxcfs/proc/uptime:/proc/uptime:rw",
]

def load_config():
    if not os.path.exists(CONFIG_PATH):
        with open(CONFIG_PATH, "w") as f: toml.dump(DEFAULT_CONFIG, f)
        return DEFAULT_CONFIG
    return toml.load(CONFIG_PATH)

config = load_config()

def require_api_key(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        key = request.headers.get("X-API-Key", "")
        if not key or not secrets.compare_digest(key, config["auth"]["api_key"]):
            return jsonify({"error": "unauthorized"}), 401
        return fn(*args, **kwargs)
    return wrapper

def parameter_sanitize_check(params: dict):
    for value in params.values():
        if value is None: continue
        if not SAFE_PARAM_RE.match(str(value)): return False
    return True

# --- Docker Logic ---

def dockercreatevps(uuid, hostname, cpu, ram, swap, network, ip, dns, image, root_password):
    host_data_dir = os.path.join(config["storage"]["base_path"], uuid)
    os.makedirs(host_data_dir, exist_ok=True)

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
        "-e", f"ROOT_PASSWORD={root_password}", # Assuming your images use this env
        "-v", f"{host_data_dir}:/data"
    ]
    
    for server in dns: cmd += ["--dns", server]
    for mount in LXCFS_MOUNTS: cmd += ["-v", mount]
    cmd += [image]

    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip())
    return result.stdout.strip()

def dockerremovevps(hostname, uuid):
    # Remove container
    subprocess.run(["docker", "rm", "-f", hostname], capture_output=True)
    # Remove files
    dir_path = os.path.join(config["storage"]["base_path"], uuid)
    if os.path.exists(dir_path):
        shutil.rmtree(dir_path)
    return hostname

# --- Routes ---

app = Flask(__name__)
APIURL = f"/api/{VERSION}"

@app.route(f"{APIURL}/dockercreatevps", methods=["POST"])
@require_api_key
def route_dockercreatevps():
    data = request.json
    try:
        # Added root_password to the call
        cid = dockercreatevps(
            data['uuid'], data['hostname'], data['cpu'], 
            data['ram'], data['swap'], data['network'], 
            data['ip'], data['dns'], data['image'], data['root_password']
        )
        return jsonify({"container_id": cid, "status": "created"}), 201
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route(f"{APIURL}/vps_action", methods=["POST"])
@require_api_key
def route_action():
    data = request.json # {container_id, action}
    action = data.get("action")
    cid = data.get("container_id")
    
    actions = {"start": "start", "stop": "stop", "restart": "restart"}
    if action not in actions: return jsonify({"error": "invalid action"}), 400
    
    res = subprocess.run(["docker", action, cid], capture_output=True, text=True)
    if res.returncode != 0: return jsonify({"error": res.stderr}), 500
    return jsonify({"status": "success"})

@app.route(f"{APIURL}/dockerstatsvps", methods=["GET"])
@require_api_key
def route_stats():
    cid = request.args.get("container_id")
    res = subprocess.run(["docker", "stats", cid, "--no-stream", "--format", "json"], capture_output=True, text=True)
    if res.returncode != 0: return jsonify({"status": "offline", "cpu_percent": 0})
    return res.stdout # Docker stats returns JSON string

if __name__ == "__main__":
    app.run(host=config["server"]["host"], port=config["server"]["port"])
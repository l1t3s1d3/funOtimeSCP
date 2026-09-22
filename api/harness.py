"""API endpoints for the AI Test Harness UI."""
import json
import os
import subprocess
import datetime
import hashlib
import shutil
import threading

import yaml
from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required

harness_bp = Blueprint('harness', __name__, url_prefix='/api/harness')

HARNESS_ROOT = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                            'ai-test-harness')
CONFIG_PATH = os.path.join(HARNESS_ROOT, 'config', 'harness.yaml')
CONFIG_EXAMPLE = os.path.join(HARNESS_ROOT, 'config', 'harness.yaml.example')
TIMELINE_PATH = os.path.join(HARNESS_ROOT, 'evidence', 'timeline.jsonl')

_running_tasks = {}


def _load_config():
    path = CONFIG_PATH if os.path.exists(CONFIG_PATH) else CONFIG_EXAMPLE
    with open(path) as f:
        return yaml.safe_load(f), os.path.exists(CONFIG_PATH)


def _save_config(data):
    os.makedirs(os.path.dirname(CONFIG_PATH), exist_ok=True)
    with open(CONFIG_PATH, 'w') as f:
        yaml.dump(data, f, default_flow_style=False, sort_keys=False)


def _read_timeline():
    if not os.path.exists(TIMELINE_PATH):
        return []
    entries = []
    with open(TIMELINE_PATH) as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    entries.append(json.loads(line))
                except json.JSONDecodeError:
                    pass
    return entries


def _log_action(action, category, details=None, artifacts=None):
    os.makedirs(os.path.dirname(TIMELINE_PATH), exist_ok=True)
    entry = {
        "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
        "action": action,
        "category": category,
        "details": details or {},
    }
    if artifacts:
        entry["artifacts"] = []
        for path in artifacts:
            abs_path = path if os.path.isabs(path) else os.path.join(HARNESS_ROOT, path)
            art = {"path": path}
            if os.path.exists(abs_path):
                with open(abs_path, "rb") as f:
                    art["sha256"] = hashlib.sha256(f.read()).hexdigest()
            entry["artifacts"].append(art)
    with open(TIMELINE_PATH, "a") as f:
        f.write(json.dumps(entry) + "\n")
    return entry


def _run_async_task(task_id, cmd, cwd, category, action_desc):
    """Run a shell command asynchronously and capture output."""
    _running_tasks[task_id] = {
        "status": "running",
        "started": datetime.datetime.utcnow().isoformat() + "Z",
        "output": "",
        "command": cmd,
    }
    try:
        result = subprocess.run(
            cmd, shell=True, cwd=cwd,
            capture_output=True, text=True, timeout=300,
        )
        _running_tasks[task_id]["output"] = result.stdout + result.stderr
        _running_tasks[task_id]["return_code"] = result.returncode
        _running_tasks[task_id]["status"] = "completed" if result.returncode == 0 else "failed"
        _log_action(action_desc, category,
                    details={"return_code": result.returncode, "task_id": task_id})
    except subprocess.TimeoutExpired:
        _running_tasks[task_id]["status"] = "timeout"
        _running_tasks[task_id]["output"] = "Command timed out after 300 seconds"
    except Exception as e:
        _running_tasks[task_id]["status"] = "error"
        _running_tasks[task_id]["output"] = str(e)


# ── Status & Setup ──────────────────────────────────────────────

@harness_bp.route('/status', methods=['GET'])
@jwt_required()
def get_status():
    """Overall harness readiness status."""
    config, is_configured = _load_config()

    checks = {
        "config_exists": is_configured,
        "harness_dir": os.path.isdir(HARNESS_ROOT),
        "evidence_dir": os.path.isdir(os.path.join(HARNESS_ROOT, 'evidence')),
        "models_dir": os.path.isdir(os.path.join(HARNESS_ROOT, 'models')),
        "api_testing_dir": os.path.isdir(os.path.join(HARNESS_ROOT, 'api-testing')),
        "network_dir": os.path.isdir(os.path.join(HARNESS_ROOT, 'network')),
        "containers_dir": os.path.isdir(os.path.join(HARNESS_ROOT, 'containers')),
    }

    tools = {}
    for tool in ['python3', 'docker', 'curl', 'jq', 'nmap', 'git']:
        tools[tool] = shutil.which(tool) is not None

    models = {
        "embedding_clean": os.path.isdir(
            os.path.join(HARNESS_ROOT, config.get('models', {}).get('embedding', {}).get('local_dir', ''))),
        "embedding_modified": os.path.isdir(
            os.path.join(HARNESS_ROOT, config.get('models', {}).get('embedding', {}).get('modified_dir', ''))),
        "reranker_clean": os.path.isdir(
            os.path.join(HARNESS_ROOT, config.get('models', {}).get('reranker', {}).get('local_dir', ''))),
        "reranker_modified": os.path.isdir(
            os.path.join(HARNESS_ROOT, config.get('models', {}).get('reranker', {}).get('modified_dir', ''))),
    }

    corpus_path = os.path.join(HARNESS_ROOT, 'api-testing', 'corpus', 'adversarial_inputs.json')

    timeline_entries = _read_timeline()

    return jsonify({
        "configured": is_configured,
        "checks": checks,
        "tools": tools,
        "models": models,
        "corpus_built": os.path.exists(corpus_path),
        "timeline_entries": len(timeline_entries),
        "engagement": config.get("engagement", {}),
    })


# ── Configuration ────────────────────────────────────────────────

@harness_bp.route('/config', methods=['GET'])
@jwt_required()
def get_config():
    config, is_configured = _load_config()
    return jsonify({"config": config, "is_configured": is_configured})


@harness_bp.route('/config', methods=['PUT'])
@jwt_required()
def save_config():
    data = request.get_json()
    if not data or 'config' not in data:
        return jsonify({"error": "Missing config data"}), 400
    _save_config(data['config'])
    _log_action("Configuration updated via UI", "setup")
    return jsonify({"message": "Configuration saved", "path": CONFIG_PATH})


# ── Evidence Timeline ────────────────────────────────────────────

@harness_bp.route('/timeline', methods=['GET'])
@jwt_required()
def get_timeline():
    entries = _read_timeline()
    category = request.args.get('category')
    if category:
        entries = [e for e in entries if e.get('category') == category]

    limit = request.args.get('limit', type=int)
    if limit:
        entries = entries[-limit:]

    categories = {}
    for e in _read_timeline():
        cat = e.get('category', 'unknown')
        categories[cat] = categories.get(cat, 0) + 1

    return jsonify({
        "entries": entries,
        "total": len(_read_timeline()),
        "categories": categories,
    })


@harness_bp.route('/timeline', methods=['POST'])
@jwt_required()
def add_timeline_entry():
    data = request.get_json()
    if not data or 'action' not in data:
        return jsonify({"error": "Missing action"}), 400
    entry = _log_action(
        data['action'],
        data.get('category', 'general'),
        details=data.get('details'),
        artifacts=data.get('artifacts'),
    )
    return jsonify({"entry": entry})


# ── Model Lab ────────────────────────────────────────────────────

@harness_bp.route('/models/status', methods=['GET'])
@jwt_required()
def models_status():
    config, _ = _load_config()
    status = {}
    for model_type in ['embedding', 'reranker']:
        m = config.get('models', {}).get(model_type, {})
        clean_dir = os.path.join(HARNESS_ROOT, m.get('local_dir', ''))
        mod_dir = os.path.join(HARNESS_ROOT, m.get('modified_dir', ''))
        status[model_type] = {
            "name": m.get('name', ''),
            "hf_repo": m.get('hf_repo', ''),
            "clean_exists": os.path.isdir(clean_dir),
            "modified_exists": os.path.isdir(mod_dir),
            "clean_file_count": len(os.listdir(clean_dir)) if os.path.isdir(clean_dir) else 0,
            "modified_file_count": len(os.listdir(mod_dir)) if os.path.isdir(mod_dir) else 0,
        }

    artifacts_dir = os.path.join(HARNESS_ROOT, 'evidence', 'artifacts')
    status["baselines"] = {
        "embedding": os.path.exists(os.path.join(artifacts_dir, 'clean_embedding_baselines.json')),
        "reranker": os.path.exists(os.path.join(artifacts_dir, 'clean_reranker_baselines.json')),
    }

    fingerprints = {}
    for f in ['embedding-clean.sha256', 'reranker-clean.sha256',
              'embedding-modified.sha256', 'reranker-modified.sha256']:
        fp = os.path.join(artifacts_dir, f)
        fingerprints[f.replace('.sha256', '')] = os.path.exists(fp)
    status["fingerprints"] = fingerprints

    return jsonify(status)


@harness_bp.route('/models/fingerprint', methods=['POST'])
@jwt_required()
def fingerprint_model():
    data = request.get_json() or {}
    model = data.get('model', 'all')
    target = data.get('target', 'clean')
    task_id = f"fingerprint_{model}_{target}_{datetime.datetime.utcnow().strftime('%H%M%S')}"
    cmd = f"cd {HARNESS_ROOT} && python3 -m scripts.model_lab fingerprint --model {model} --target {target}"
    t = threading.Thread(target=_run_async_task,
                         args=(task_id, cmd, HARNESS_ROOT, "model-lab",
                               f"Fingerprint {model} ({target})"))
    t.start()
    return jsonify({"task_id": task_id, "message": "Fingerprinting started"})


# ── API Testing ──────────────────────────────────────────────────

@harness_bp.route('/api-testing/corpus', methods=['GET'])
@jwt_required()
def corpus_status():
    corpus_path = os.path.join(HARNESS_ROOT, 'api-testing', 'corpus', 'adversarial_inputs.json')
    if not os.path.exists(corpus_path):
        return jsonify({"exists": False})

    with open(corpus_path) as f:
        corpus = json.load(f)

    return jsonify({
        "exists": True,
        "metadata": corpus.get("metadata", {}),
        "categories": list(corpus.get("embed_inputs", {}).keys()),
        "file_size": os.path.getsize(corpus_path),
    })


@harness_bp.route('/api-testing/corpus/build', methods=['POST'])
@jwt_required()
def build_corpus():
    task_id = f"corpus_{datetime.datetime.utcnow().strftime('%H%M%S')}"
    cmd = f"cd {HARNESS_ROOT} && python3 api-testing/scripts/build_corpus.py"
    t = threading.Thread(target=_run_async_task,
                         args=(task_id, cmd, HARNESS_ROOT, "api-testing",
                               "Built adversarial corpus"))
    t.start()
    return jsonify({"task_id": task_id, "message": "Building corpus..."})


@harness_bp.route('/api-testing/fuzz', methods=['POST'])
@jwt_required()
def run_fuzz():
    data = request.get_json() or {}
    config, _ = _load_config()
    host = data.get('host', config.get('tei', {}).get('host', 'http://localhost:8080'))
    endpoint = data.get('endpoint', 'all')
    task_id = f"fuzz_{datetime.datetime.utcnow().strftime('%H%M%S')}"
    cmd = f"cd {HARNESS_ROOT} && python3 api-testing/scripts/fuzz_tei.py {host} --endpoint {endpoint}"
    t = threading.Thread(target=_run_async_task,
                         args=(task_id, cmd, HARNESS_ROOT, "api-testing",
                               f"API fuzz against {host}"))
    t.start()
    return jsonify({"task_id": task_id, "message": f"Fuzzing {host}..."})


@harness_bp.route('/api-testing/auth-test', methods=['POST'])
@jwt_required()
def run_auth_test():
    data = request.get_json() or {}
    config, _ = _load_config()
    host = data.get('host', config.get('tei', {}).get('host', 'http://localhost:8080'))
    task_id = f"auth_{datetime.datetime.utcnow().strftime('%H%M%S')}"
    cmd = f"cd {HARNESS_ROOT} && python3 api-testing/scripts/auth_tests.py {host}"
    t = threading.Thread(target=_run_async_task,
                         args=(task_id, cmd, HARNESS_ROOT, "api-testing",
                               f"Auth tests against {host}"))
    t.start()
    return jsonify({"task_id": task_id, "message": f"Running auth tests against {host}..."})


@harness_bp.route('/api-testing/results', methods=['GET'])
@jwt_required()
def list_results():
    results_dir = os.path.join(HARNESS_ROOT, 'api-testing', 'results')
    if not os.path.isdir(results_dir):
        return jsonify({"results": []})

    files = []
    for f in sorted(os.listdir(results_dir), reverse=True):
        fp = os.path.join(results_dir, f)
        if os.path.isfile(fp):
            files.append({
                "name": f,
                "size": os.path.getsize(fp),
                "modified": datetime.datetime.fromtimestamp(
                    os.path.getmtime(fp)).isoformat() + "Z",
            })
    return jsonify({"results": files})


@harness_bp.route('/api-testing/results/<filename>', methods=['GET'])
@jwt_required()
def get_result_file(filename):
    results_dir = os.path.join(HARNESS_ROOT, 'api-testing', 'results')
    filepath = os.path.join(results_dir, filename)
    if not os.path.exists(filepath) or '..' in filename:
        return jsonify({"error": "Not found"}), 404

    entries = []
    with open(filepath) as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    entries.append(json.loads(line))
                except json.JSONDecodeError:
                    pass

    if not entries and filepath.endswith('.json'):
        with open(filepath) as f:
            return jsonify(json.load(f))

    return jsonify({"entries": entries, "total": len(entries)})


# ── Network Testing ──────────────────────────────────────────────

@harness_bp.route('/network/probe', methods=['POST'])
@jwt_required()
def run_egress_probe():
    task_id = f"egress_{datetime.datetime.utcnow().strftime('%H%M%S')}"
    out_file = os.path.join(HARNESS_ROOT, 'evidence', 'artifacts',
                            f'egress_probe_{task_id}.json')
    cmd = f"bash {HARNESS_ROOT}/network/egress-tests/egress_probe.sh {out_file}"
    t = threading.Thread(target=_run_async_task,
                         args=(task_id, cmd, HARNESS_ROOT, "network",
                               "Ran egress probe"))
    t.start()
    return jsonify({"task_id": task_id, "message": "Egress probe started..."})


@harness_bp.route('/network/lateral', methods=['POST'])
@jwt_required()
def run_lateral_probe():
    task_id = f"lateral_{datetime.datetime.utcnow().strftime('%H%M%S')}"
    out_file = os.path.join(HARNESS_ROOT, 'evidence', 'artifacts',
                            f'lateral_probe_{task_id}.txt')
    cmd = f"bash {HARNESS_ROOT}/network/egress-tests/lateral_probe.sh {out_file}"
    t = threading.Thread(target=_run_async_task,
                         args=(task_id, cmd, HARNESS_ROOT, "network",
                               "Ran lateral movement probe"))
    t.start()
    return jsonify({"task_id": task_id, "message": "Lateral probe started..."})


# ── Container Pipeline ───────────────────────────────────────────

@harness_bp.route('/containers/status', methods=['GET'])
@jwt_required()
def container_status():
    clean_df = os.path.exists(os.path.join(HARNESS_ROOT, 'containers', 'clean', 'Dockerfile'))
    mod_dfs = []
    mod_dir = os.path.join(HARNESS_ROOT, 'containers', 'modified')
    if os.path.isdir(mod_dir):
        mod_dfs = [f for f in os.listdir(mod_dir) if f.startswith('Dockerfile')]

    docker_available = shutil.which('docker') is not None
    images = []
    if docker_available:
        try:
            result = subprocess.run(
                ['docker', 'images', '--format', '{{.Repository}}:{{.Tag}} {{.Size}} {{.CreatedAt}}',
                 '--filter', 'reference=harness/*'],
                capture_output=True, text=True, timeout=10)
            for line in result.stdout.strip().split('\n'):
                if line.strip():
                    images.append(line.strip())
        except Exception:
            pass

    return jsonify({
        "clean_dockerfile": clean_df,
        "modified_dockerfiles": mod_dfs,
        "docker_available": docker_available,
        "harness_images": images,
    })


@harness_bp.route('/containers/build', methods=['POST'])
@jwt_required()
def build_containers():
    task_id = f"build_{datetime.datetime.utcnow().strftime('%H%M%S')}"
    cmd = f"bash {HARNESS_ROOT}/containers/build.sh"
    t = threading.Thread(target=_run_async_task,
                         args=(task_id, cmd, HARNESS_ROOT, "container-pipeline",
                               "Built container images"))
    t.start()
    return jsonify({"task_id": task_id, "message": "Container build started..."})


# ── Task Management ──────────────────────────────────────────────

@harness_bp.route('/tasks', methods=['GET'])
@jwt_required()
def list_tasks():
    return jsonify({"tasks": dict(_running_tasks)})


@harness_bp.route('/tasks/<task_id>', methods=['GET'])
@jwt_required()
def get_task(task_id):
    if task_id not in _running_tasks:
        return jsonify({"error": "Task not found"}), 404
    return jsonify({"task": _running_tasks[task_id]})


# ── Checklist ────────────────────────────────────────────────────

CHECKLIST_PATH = os.path.join(HARNESS_ROOT, 'config', 'checklist.json')


@harness_bp.route('/checklist', methods=['GET'])
@jwt_required()
def get_checklist():
    if os.path.exists(CHECKLIST_PATH):
        with open(CHECKLIST_PATH) as f:
            return jsonify(json.load(f))
    return jsonify({"items": _default_checklist()})


@harness_bp.route('/checklist', methods=['PUT'])
@jwt_required()
def update_checklist():
    data = request.get_json()
    os.makedirs(os.path.dirname(CHECKLIST_PATH), exist_ok=True)
    with open(CHECKLIST_PATH, 'w') as f:
        json.dump(data, f, indent=2)
    return jsonify({"message": "Checklist saved"})


def _default_checklist():
    return [
        {"id": "arch", "phase": "Phase 0", "text": "Architecture package received", "done": False},
        {"id": "env", "phase": "Phase 0", "text": "Python environment & Docker configured", "done": False},
        {"id": "dirs", "phase": "Phase 0", "text": "Project directory structure created", "done": False},
        {"id": "aws", "phase": "Phase 0", "text": "AWS CLI configured with test profile", "done": False},
        {"id": "models_dl", "phase": "Phase 1", "text": "Clean models downloaded", "done": False},
        {"id": "models_fp", "phase": "Phase 1", "text": "Clean models fingerprinted (SHA-256)", "done": False},
        {"id": "baselines", "phase": "Phase 1", "text": "Clean inference baselines generated", "done": False},
        {"id": "tei_local", "phase": "Phase 1", "text": "Local TEI server tested with clean models", "done": False},
        {"id": "models_mod", "phase": "Phase 1", "text": "Modified model variants developed", "done": False},
        {"id": "models_val", "phase": "Phase 1", "text": "Modified models pass functional testing", "done": False},
        {"id": "img_arch", "phase": "Phase 2", "text": "Target container image architecture understood", "done": False},
        {"id": "img_clean", "phase": "Phase 2", "text": "Clean reproduction Dockerfile built", "done": False},
        {"id": "img_mod", "phase": "Phase 2", "text": "Modified Dockerfiles built and tested", "done": False},
        {"id": "ecr_push", "phase": "Phase 2", "text": "ECR push workflow tested", "done": False},
        {"id": "cicd", "phase": "Phase 2", "text": "CI/CD injection approach planned", "done": False},
        {"id": "test_env", "phase": "Phase 3", "text": "Test environment confirmed ready", "done": False},
        {"id": "vpn", "phase": "Phase 3", "text": "VPN/remote access verified", "done": False},
        {"id": "creds", "phase": "Phase 3", "text": "Test credentials received and validated", "done": False},
        {"id": "egress", "phase": "Phase 3", "text": "Egress probe scripts tested", "done": False},
        {"id": "callback", "phase": "Phase 3", "text": "Callback infrastructure deployed", "done": False},
        {"id": "corpus", "phase": "Phase 4", "text": "Adversarial input corpus built", "done": False},
        {"id": "fuzz", "phase": "Phase 4", "text": "API fuzzing scripts tested", "done": False},
        {"id": "auth", "phase": "Phase 4", "text": "Auth test scripts ready", "done": False},
        {"id": "evidence", "phase": "Phase 5", "text": "Evidence capture scripts tested", "done": False},
        {"id": "timeline", "phase": "Phase 5", "text": "Timeline initialized", "done": False},
        {"id": "telemetry", "phase": "Phase 5", "text": "Telemetry sources confirmed active", "done": False},
    ]

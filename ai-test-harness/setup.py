#!/usr/bin/env python3
"""
AI Test Harness — Setup & Install

Interactive installer that checks prerequisites, installs Python
dependencies, creates directory structure, and initializes config.

Phases can be selected individually so operators only install what
they need for their current workstream.

Usage:
    python setup.py                # Interactive full setup
    python setup.py --phases 0,1   # Only Phase 0 (base) and Phase 1 (models)
    python setup.py --check        # Prereq check only, no install
    python setup.py --list         # List phases and exit
"""
import os
import shutil
import subprocess
import sys

HARNESS_ROOT = os.path.dirname(os.path.abspath(__file__))

PHASES = {
    0: {
        "name": "Base Setup",
        "description": "Python deps, directory structure, config file",
        "system_tools": [],
        "optional_tools": [],
        "pip_packages": [
            "pyyaml", "click", "rich",
        ],
        "directories": [
            "config", "scripts", "evidence", "evidence/screenshots",
            "evidence/logs", "evidence/artifacts", "reporting/templates",
            "reporting/drafts",
        ],
    },
    1: {
        "name": "ML Model Lab",
        "description": "Download, fingerprint, and baseline ML models",
        "system_tools": [],
        "optional_tools": [],
        "pip_packages": [
            "torch", "transformers", "sentence-transformers",
            "safetensors", "huggingface-hub", "numpy",
        ],
        "directories": [
            "models/clean", "models/modified",
        ],
    },
    2: {
        "name": "Container Pipeline",
        "description": "Build and manage Docker container images",
        "system_tools": ["docker"],
        "optional_tools": ["docker-compose"],
        "pip_packages": [
            "docker",
        ],
        "directories": [
            "containers/clean", "containers/modified",
        ],
    },
    3: {
        "name": "Network & Exfiltration",
        "description": "Egress probes, lateral movement, VPC mapping",
        "system_tools": ["curl"],
        "optional_tools": ["nmap", "tcpdump"],
        "pip_packages": [
            "httpx", "requests",
        ],
        "directories": [
            "network/egress-tests", "network/callback-infra",
        ],
    },
    4: {
        "name": "API Testing",
        "description": "Fuzz TEI endpoints, auth testing, corpus building",
        "system_tools": ["curl"],
        "optional_tools": ["jq"],
        "pip_packages": [
            "httpx", "requests",
        ],
        "directories": [
            "api-testing/corpus", "api-testing/scripts", "api-testing/results",
        ],
    },
    5: {
        "name": "Evidence & Reporting",
        "description": "Timeline capture, report generation, evidence export",
        "system_tools": [],
        "optional_tools": ["aws"],
        "pip_packages": [
            "jinja2", "pandas", "matplotlib",
        ],
        "directories": [
            "evidence", "evidence/screenshots", "evidence/logs",
            "evidence/artifacts", "reporting/templates", "reporting/drafts",
        ],
    },
}


def color(text, code):
    return f"\033[{code}m{text}\033[0m"


def green(text):
    return color(text, "32")


def red(text):
    return color(text, "31")


def yellow(text):
    return color(text, "33")


def cyan(text):
    return color(text, "36")


def bold(text):
    return color(text, "1")


def check_tool(name):
    return shutil.which(name) is not None


IMPORT_NAME_MAP = {
    "pyyaml": "yaml",
    "sentence-transformers": "sentence_transformers",
    "huggingface-hub": "huggingface_hub",
    "pillow": "PIL",
    "scikit-learn": "sklearn",
}


def check_python_package(name):
    import_name = IMPORT_NAME_MAP.get(name, name.replace("-", "_"))
    try:
        __import__(import_name)
        return True
    except ImportError:
        return False


def list_phases():
    print(f"\n{bold('Available Phases:')}\n")
    for num, phase in PHASES.items():
        print(f"  {cyan(str(num))}  {bold(phase['name'])}")
        print(f"     {phase['description']}")
        if phase["system_tools"]:
            print(f"     System tools: {', '.join(phase['system_tools'])}")
        if phase["optional_tools"]:
            print(f"     Optional tools: {', '.join(phase['optional_tools'])}")
        if phase["pip_packages"]:
            print(f"     Python packages: {', '.join(phase['pip_packages'])}")
        print()


def check_prerequisites(selected_phases):
    print(f"\n{bold('Checking prerequisites...')}\n")

    all_ok = True
    missing_required = []
    missing_optional = []
    missing_packages = []

    for num in selected_phases:
        phase = PHASES[num]
        name = phase["name"]
        print(f"  {bold(f'Phase {num}: {name}')}")

        for tool in phase["system_tools"]:
            ok = check_tool(tool)
            status = green("OK") if ok else red("MISSING")
            print(f"    {tool:20s} {status}")
            if not ok:
                missing_required.append((num, tool))
                all_ok = False

        for tool in phase["optional_tools"]:
            ok = check_tool(tool)
            status = green("OK") if ok else yellow("OPTIONAL")
            print(f"    {tool:20s} {status}")
            if not ok:
                missing_optional.append((num, tool))

        for pkg in phase["pip_packages"]:
            ok = check_python_package(pkg)
            status = green("OK") if ok else yellow("NEEDED")
            print(f"    {pkg:20s} {status}")
            if not ok:
                missing_packages.append(pkg)

        print()

    return all_ok, missing_required, missing_optional, missing_packages


def install_packages(packages):
    unique = list(dict.fromkeys(packages))
    if not unique:
        return True

    print(f"\n{bold('Installing Python packages...')}")
    print(f"  {', '.join(unique)}\n")

    cmd = [sys.executable, "-m", "pip", "install"] + unique
    result = subprocess.run(cmd, capture_output=False)
    return result.returncode == 0


def create_directories(selected_phases):
    print(f"\n{bold('Creating directories...')}")
    created = 0
    for num in selected_phases:
        for d in PHASES[num]["directories"]:
            path = os.path.join(HARNESS_ROOT, d)
            if not os.path.exists(path):
                os.makedirs(path, exist_ok=True)
                print(f"  {green('+')} {d}")
                created += 1
    if created == 0:
        print(f"  {green('All directories already exist')}")
    else:
        print(f"  {green(f'Created {created} directories')}")


def setup_config():
    config_path = os.path.join(HARNESS_ROOT, "config", "harness.yaml")
    example_path = os.path.join(HARNESS_ROOT, "config", "harness.yaml.example")

    if os.path.exists(config_path):
        print(f"\n  {green('Config already exists:')} config/harness.yaml")
        return

    if os.path.exists(example_path):
        shutil.copy2(example_path, config_path)
        print(f"\n  {green('Created config from template:')} config/harness.yaml")
        print(f"  {yellow('Edit config/harness.yaml with your target details')}")
    else:
        print(f"\n  {yellow('No config template found.')} Create config/harness.yaml manually.")


def print_install_hints(missing_required, missing_optional):
    if not missing_required and not missing_optional:
        return

    print(f"\n{bold('Install hints for missing system tools:')}\n")

    all_missing = [(t, True) for _, t in missing_required] + \
                  [(t, False) for _, t in missing_optional]

    hints = {
        "docker": "curl -fsSL https://get.docker.com | sh",
        "docker-compose": "pip install docker-compose  # or: sudo apt install docker-compose",
        "curl": "sudo apt install curl",
        "nmap": "sudo apt install nmap",
        "tcpdump": "sudo apt install tcpdump",
        "jq": "sudo apt install jq",
        "aws": "pip install awscli  # or: curl https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip -o awscliv2.zip && unzip awscliv2.zip && sudo ./aws/install",
    }

    seen = set()
    for tool, required in all_missing:
        if tool in seen:
            continue
        seen.add(tool)
        label = red("REQUIRED") if required else yellow("OPTIONAL")
        hint = hints.get(tool, f"Install {tool} via your package manager")
        print(f"  {tool:18s} [{label}]")
        print(f"    {cyan(hint)}")


def interactive_phase_select():
    list_phases()
    print(f"{bold('Select phases to install:')}")
    print(f"  Press Enter for all, or type phase numbers (e.g. 0,1,3)")
    print(f"  Phase 0 (Base) is always included.\n")

    try:
        choice = input(f"  Phases [{cyan('0-5')}]: ").strip()
    except (EOFError, KeyboardInterrupt):
        print()
        sys.exit(0)

    if not choice:
        return list(PHASES.keys())

    selected = set()
    for part in choice.replace(" ", ",").split(","):
        part = part.strip()
        if part.isdigit() and int(part) in PHASES:
            selected.add(int(part))
        elif part:
            print(f"  {yellow(f'Unknown phase: {part}')}")

    selected.add(0)
    return sorted(selected)


def main():
    print(f"\n{bold('=' * 50)}")
    print(f"{bold('  AI Test Harness — Setup')}")
    print(f"{bold('=' * 50)}")

    if "--list" in sys.argv:
        list_phases()
        return 0

    if "--phases" in sys.argv:
        idx = sys.argv.index("--phases")
        if idx + 1 < len(sys.argv):
            phases_str = sys.argv[idx + 1]
            selected = set()
            for p in phases_str.split(","):
                p = p.strip()
                if p.isdigit() and int(p) in PHASES:
                    selected.add(int(p))
            selected.add(0)
            selected = sorted(selected)
        else:
            print(red("--phases requires a comma-separated list (e.g. 0,1,3)"))
            return 1
    elif "--check" in sys.argv:
        selected = list(PHASES.keys())
    else:
        selected = interactive_phase_select()

    phase_names = ", ".join(f"{n}: {PHASES[n]['name']}" for n in selected)
    print(f"\n{bold('Selected phases:')} {phase_names}\n")

    all_ok, missing_req, missing_opt, missing_pkgs = check_prerequisites(selected)

    if "--check" in sys.argv:
        print_install_hints(missing_req, missing_opt)
        if all_ok and not missing_pkgs:
            print(f"\n{green(bold('All prerequisites met.'))}")
        elif not all_ok:
            print(f"\n{red(bold('Some required tools are missing.'))}")
        else:
            print(f"\n{yellow(bold('System tools OK. Some Python packages need installing.'))}")
        return 0 if all_ok else 1

    print_install_hints(missing_req, missing_opt)

    if missing_req:
        print(f"\n{yellow('Required system tools are missing (see above).')}")
        print(f"Install them first, or continue to set up what's available.\n")
        try:
            cont = input(f"  Continue anyway? [{cyan('y/N')}]: ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            print()
            return 1
        if cont != "y":
            return 1

    if missing_pkgs:
        install_packages(missing_pkgs)

    create_directories(selected)
    setup_config()

    print(f"\n{bold('=' * 50)}")
    print(f"{green(bold('  Setup complete!'))}")
    print(f"{bold('=' * 50)}")

    print(f"\n{bold('Next steps:')}")
    print(f"  1. Edit {cyan('config/harness.yaml')} with target details")
    print(f"  2. Run {cyan('python scripts/setup_check.py')} to verify")

    if 1 in selected:
        print(f"  3. Run {cyan('python scripts/model_lab.py download')} to pull models")
    if 2 in selected:
        print(f"  4. Ensure Docker is running, then {cyan('bash containers/build.sh')}")
    if 3 in selected:
        print(f"  5. Review network scripts in {cyan('network/')}")
    if 4 in selected:
        print(f"  6. Build corpus: {cyan('python api-testing/scripts/build_corpus.py')}")
    print()

    return 0


if __name__ == "__main__":
    sys.exit(main())

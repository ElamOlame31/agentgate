"""
Policy template loader — apply compliance templates to an AgentGate server.

Usage:
    from templates.loader import apply_template

    apply_template("soc2",               agentgate_url="http://localhost:8000", api_key="...")
    apply_template("hipaa",              agentgate_url="http://localhost:8000", api_key="...")
    apply_template("gdpr",               agentgate_url="http://localhost:8000", api_key="...")
    apply_template("financial_services", agentgate_url="http://localhost:8000", api_key="...")

CLI:
    python -m templates.loader soc2 --url http://localhost:8000 --key your-key
"""

import os
import yaml
import httpx
from pathlib import Path

TEMPLATES_DIR = Path(__file__).parent

AVAILABLE = ["soc2", "hipaa", "gdpr", "financial_services"]


def load_template(name: str) -> dict:
    path = TEMPLATES_DIR / f"{name}.yaml"
    if not path.exists():
        raise FileNotFoundError(
            f"Template '{name}' not found. Available: {AVAILABLE}"
        )
    with open(path, encoding="utf-8") as f:
        return yaml.safe_load(f)


def apply_template(
    name: str,
    agentgate_url: str = "http://localhost:8000",
    api_key: str = "",
) -> dict:
    """
    Load a compliance template and push its policies to an AgentGate server.
    Returns a summary of what was applied.
    """
    template = load_template(name)
    headers  = {"X-API-Key": api_key} if api_key else {}
    base     = agentgate_url.rstrip("/")
    applied  = []
    failed   = []

    print(f"[AgentGate] Applying template: {template['name']}")
    print(f"[AgentGate] {len(template.get('policies', []))} policies to load...")

    for policy in template.get("policies", []):
        try:
            r = httpx.post(
                f"{base}/policies",
                headers=headers,
                json={"rule": policy["rule"]},
                timeout=10.0,
            )
            if r.status_code in (200, 201):
                applied.append(policy["name"])
                print(f"  [+] {policy['name']}")
            else:
                failed.append(policy["name"])
                print(f"  [!] {policy['name']}: {r.status_code}")
        except Exception as e:
            failed.append(policy["name"])
            print(f"  [!] {policy['name']}: {e}")

    print(f"\n[AgentGate] Template applied: {len(applied)} ok, {len(failed)} failed")
    return {"applied": applied, "failed": failed, "template": template["name"]}


def list_templates() -> list[dict]:
    templates = []
    for name in AVAILABLE:
        try:
            t = load_template(name)
            templates.append({
                "name":        name,
                "title":       t["name"],
                "description": t.get("description", "").strip(),
                "policies":    len(t.get("policies", [])),
            })
        except Exception:
            pass
    return templates


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Apply an AgentGate compliance template")
    parser.add_argument("template", choices=AVAILABLE, help="Template to apply")
    parser.add_argument("--url",  default="http://localhost:8000", help="AgentGate server URL")
    parser.add_argument("--key",  default="",                      help="API key")
    parser.add_argument("--list", action="store_true",             help="List available templates")
    args = parser.parse_args()

    if args.list:
        for t in list_templates():
            print(f"\n{t['title']} ({t['name']})")
            print(f"  {t['description'][:100]}...")
            print(f"  {t['policies']} policies")
    else:
        apply_template(args.template, agentgate_url=args.url, api_key=args.key)

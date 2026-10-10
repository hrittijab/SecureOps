
import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]

SCENARIOS = {
    "bola_prevention": {
        "script": "attacks/live_bola_replay.py",
        "report": "results/live_bola_replay.json",
    },
    "jwt_integrity": {
        "script": "attacks/jwt_attack_replay.py",
        "report": "results/jwt_attack_replay.json",
    },
    "jwt_claim_validation": {
        "script": "attacks/jwt_claims_replay.py",
        "report": "results/jwt_claims_replay.json",
    },
}


def run_scenario(name, config):
    script = ROOT / config["script"]
    report_path = ROOT / config["report"]

    if not script.is_file():
        return {
            "passed": False,
            "error": f"Missing script: {config['script']}",
        }

    # Prevent an old report from being treated as fresh.
    report_path.unlink(missing_ok=True)

    try:
        process = subprocess.run(
            [sys.executable, str(script)],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=120,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return {
            "passed": False,
            "error": "Scenario timed out after 120 seconds",
        }

    if not report_path.is_file():
        return {
            "passed": False,
            "exit_code": process.returncode,
            "error": "Scenario did not generate a report",
            "stdout": process.stdout[-2000:],
            "stderr": process.stderr[-2000:],
        }

    try:
        report = json.loads(
            report_path.read_text(encoding="utf-8")
        )
    except (json.JSONDecodeError, OSError) as error:
        return {
            "passed": False,
            "exit_code": process.returncode,
            "error": f"Invalid report: {error}",
        }

    return {
        "passed": (
            process.returncode == 0
            and report.get("passed") is True
        ),
        "exit_code": process.returncode,
        "report_file": config["report"],
        "results": report.get(
            "results",
            report.get("checks", {}),
        ),
    }


def run():
    print("\n[SecureOps JWT Security Evaluation Suite]")

    scenario_results = {}

    for name, config in SCENARIOS.items():
        print(f"\nRunning {name}...", flush=True)

        result = run_scenario(name, config)
        scenario_results[name] = result

        status = "PASS" if result["passed"] else "FAIL"
        print(f"{status} {name}")

        if "error" in result:
            print(f"  Error: {result['error']}")

    passed_count = sum(
        result["passed"]
        for result in scenario_results.values()
    )

    total = len(scenario_results)

    summary = {
        "experiment": "secureops_jwt_security_suite",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "total_scenarios": total,
        "passed_scenarios": passed_count,
        "failed_scenarios": total - passed_count,
        "pass_rate": round(passed_count / total, 4),
        "scenarios": scenario_results,
        "passed": passed_count == total,
    }

    output = ROOT / "results" / "jwt_security_suite.json"
    output.parent.mkdir(parents=True, exist_ok=True)

    output.write_text(
        json.dumps(summary, indent=2),
        encoding="utf-8",
    )

    print("\n" + "=" * 42)
    print("SECUREOPS JWT SECURITY SUMMARY")
    print("=" * 42)
    print(f"Passed: {passed_count}/{total}")
    print(f"Pass rate: {summary['pass_rate'] * 100:.1f}%")
    print(f"Overall: {'PASS' if summary['passed'] else 'FAIL'}")
    print(f"Report: {output.relative_to(ROOT)}")

    return summary


if __name__ == "__main__":
    result = run()
    sys.exit(0 if result["passed"] else 1)

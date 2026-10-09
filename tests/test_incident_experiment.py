from evaluation.incident_experiment import (
    generate_attack_events,
    generate_bola_events,
    run_experiment,
)

from detection.rules.brute_force import detect as brute_force
from detection.rules.password_spray import detect as password_spray
from detection.rules.slow_password_spray import detect as slow_spray
from detection.rules.bola import detect as bola


def test_brute_force_detected():
    assert brute_force(generate_attack_events())


def test_password_spray_detected():
    assert password_spray(generate_attack_events())


def test_slow_password_spray_detected():
    assert slow_spray(generate_attack_events())


def test_bola_detected():
    assert bola(generate_bola_events())


def test_full_incident_experiment():
    report = run_experiment()

    assert report["passed"] is True
    assert len(report["incidents"]) == 1
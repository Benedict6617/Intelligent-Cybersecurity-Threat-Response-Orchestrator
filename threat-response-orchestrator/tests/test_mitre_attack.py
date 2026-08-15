from app.core import mitre_attack


def test_techniques_for_event_type_matches():
    matches = mitre_attack.techniques_for_event_type("authentication_failure")
    assert any(t.id == "T1110" for t in matches)


def test_techniques_for_event_type_no_match():
    assert mitre_attack.techniques_for_event_type("totally_unknown_event_type") == []


def test_tactic_progression_score_full_chain_scores_high():
    chain = ["Initial Access", "Execution", "Credential Access", "Lateral Movement", "Exfiltration", "Impact"]
    score = mitre_attack.tactic_progression_score(chain)
    assert score > 0.5


def test_tactic_progression_score_single_tactic_scores_low():
    score = mitre_attack.tactic_progression_score(["Discovery"])
    assert score < 0.15


def test_tactic_progression_score_empty():
    assert mitre_attack.tactic_progression_score([]) == 0.0

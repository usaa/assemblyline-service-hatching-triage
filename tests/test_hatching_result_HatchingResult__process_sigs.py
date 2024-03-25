import pytest
import json
import logging as log

from assemblyline_v4_service.common.result import BODY_FORMAT
from .utils import hatching_result_instance


def test_process_sigs(
    hatching_result_instance: hatching_result_instance,
):
    """Validate the happy path. A single sig as input and the appropriate output created."""

    # Example data created from a static or dynamic analysis report: signatures[]
    hatching_sigs = [
        {
            "name": "Ramnit family",
            "score": 10,
            "tags": ["family:ramnit"],
            "ttp": ["T1005", "T1552.001"],
        },
    ]

    sigs = hatching_result_instance._process_sigs(hatching_sigs=hatching_sigs)

    assert sigs is not None
    assert len(sigs) == 1

    sigd = sigs[0]
    assert sigd.get("hatching_sig") == hatching_sigs[0]

    ontres_sig = sigd.get("ontres_sig")
    assert ontres_sig is not None
    assert ontres_sig.name == "Ramnit family"
    assert ontres_sig.type == "CUCKOO"
    assert ontres_sig.score == 1000
    assert ontres_sig.malware_families == ["ramnit"]
    assert ontres_sig.attacks == [
        {
            "attack_id": "T1005",
            "categories": ["collection"],
            "pattern": "Data from Local System",
        },
        {
            "attack_id": "T1552.001",
            "categories": ["credential-access"],
            "pattern": "Credentials In Files",
        },
    ]


def test_warning_logged_for_invalid_attackid(
    hatching_result_instance: hatching_result_instance, caplog
):
    """Validate a warning is logged when an invalid attack_id is parsed from the hatching results.
    Everything else should still process. That invalid TTP will simply be logged.
    """

    # Example data created from a static or dynamic analysis report: signatures[]
    hatching_sigs = [
        {
            "name": "Ramnit family",
            "score": 10,
            "tags": ["family:ramnit"],
            "ttp": ["TINVALID", "T1552.001"],
        },
    ]

    sigs = hatching_result_instance._process_sigs(hatching_sigs=hatching_sigs)

    assert sigs is not None
    assert len(sigs) == 1

    sigd = sigs[0]
    assert sigd.get("hatching_sig") == hatching_sigs[0]

    ontres_sig = sigd.get("ontres_sig")
    assert ontres_sig is not None
    assert ontres_sig.name == "Ramnit family"
    assert ontres_sig.type == "CUCKOO"
    assert ontres_sig.score == 1000
    assert ontres_sig.malware_families == ["ramnit"]
    assert ontres_sig.attacks == [
        {
            "attack_id": "T1552.001",
            "categories": ["credential-access"],
            "pattern": "Credentials In Files",
        },
    ]

    warnings = [
        record for record in caplog.get_records("call") if record.levelno >= log.WARNING
    ]
    assert f"attack_id not found in the attack_map. attack_id: TINVALID" in caplog.text
    assert len(warnings) == 1


def test_with_multiple_sigs(
    hatching_result_instance: hatching_result_instance,
):
    """Validate expected output when multiple sigs in the input"""
    #
    # test with multiple sigs in input
    #
    hatching_sigs = [
        {
            "name": "Ramnit family",
            "score": 6,
        },
        {
            "name": "testfam2",
            "score": 0,
        },
    ]

    sigs = hatching_result_instance._process_sigs(hatching_sigs=hatching_sigs)

    assert sigs is not None
    assert len(sigs) == 2

    sigd = sigs[0]
    assert sigd.get("hatching_sig") == hatching_sigs[0]

    ontres_sig = sigd.get("ontres_sig")
    assert ontres_sig is not None
    assert ontres_sig.name == "Ramnit family"
    assert ontres_sig.type == "CUCKOO"
    assert ontres_sig.score == 600
    assert ontres_sig.malware_families == []
    assert ontres_sig.attacks == []

    sigd = sigs[1]
    assert sigd.get("hatching_sig") == hatching_sigs[1]

    ontres_sig = sigd.get("ontres_sig")
    assert ontres_sig is not None
    assert ontres_sig.name == "testfam2"
    assert ontres_sig.type == "CUCKOO"
    assert ontres_sig.score == 0
    assert ontres_sig.malware_families == []
    assert ontres_sig.attacks == []


def test_hatching_to_al_score_mapping(
    hatching_result_instance: hatching_result_instance,
):
    """Validate the score mapping from Hatching's score to the AL4 is as expected."""

    # Example data created from a static or dynamic analysis report: signatures[]
    hatching_sigs = [
        {"name": "fam1", "score": 0},
    ]
    sigs = hatching_result_instance._process_sigs(hatching_sigs=hatching_sigs)
    assert sigs[0].get("ontres_sig").score == 0

    hatching_sigs = [
        {"name": "fam1", "score": 1},
    ]
    sigs = hatching_result_instance._process_sigs(hatching_sigs=hatching_sigs)
    assert sigs[0].get("ontres_sig").score == 0

    hatching_sigs = [
        {"name": "fam1", "score": 5},
    ]
    sigs = hatching_result_instance._process_sigs(hatching_sigs=hatching_sigs)
    assert sigs[0].get("ontres_sig").score == 0

    hatching_sigs = [
        {"name": "fam1", "score": 6},
    ]
    sigs = hatching_result_instance._process_sigs(hatching_sigs=hatching_sigs)
    assert sigs[0].get("ontres_sig").score == 600

    hatching_sigs = [
        {"name": "fam1", "score": 8},
    ]
    sigs = hatching_result_instance._process_sigs(hatching_sigs=hatching_sigs)
    assert sigs[0].get("ontres_sig").score == 800

    hatching_sigs = [
        {"name": "fam1", "score": 10},
    ]
    sigs = hatching_result_instance._process_sigs(hatching_sigs=hatching_sigs)
    assert sigs[0].get("ontres_sig").score == 1000

    #
    # Validate a score out of range from the 0-10 map will just return an AL4 score of 0

    hatching_sigs = [
        {"name": "fam1", "score": 11},
    ]
    sigs = hatching_result_instance._process_sigs(hatching_sigs=hatching_sigs)
    assert sigs[0].get("ontres_sig").score == 0


def test_returns_empty_list(
    hatching_result_instance: hatching_result_instance,
):
    """Validate an empty list is returned when no sigs found in input"""

    # Example data created from a static or dynamic analysis report: signatures[]
    hatching_sigs = []
    sigs = hatching_result_instance._process_sigs(hatching_sigs=hatching_sigs)
    assert sigs == []

    hatching_sigs = None
    sigs = hatching_result_instance._process_sigs(hatching_sigs=hatching_sigs)
    assert sigs == []

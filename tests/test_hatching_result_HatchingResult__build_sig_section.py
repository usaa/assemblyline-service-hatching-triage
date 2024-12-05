"""Validate the this function that creates a Malware Signature Section with a sub-section per signature.
The individual methods that build each sub-section has more thorough unit tests for each sub-section's capabilities.
"""
import pytest
import json
import logging as log

from assemblyline_v4_service.common.result import BODY_FORMAT
from .utils import hatching_result_instance


def test_build_sig_section(
    hatching_result_instance: hatching_result_instance,
):
    """Validate the happy path.

    Validate a ResultSection is created with sub-sections for each Hatching Sig

    Validate sigs are also added appropriately to the ontology results
    """

    # A minimized/fake set of results to validate all sections show up
    hatching_sigs = [
        {
            "name": "Test Sig 1",
            "score": 10,
            "tags": ["family:test"],
            "ttp": ["T1006", "T1552.001"],
            "desc": "test description 1",
        },
        {
            "name": "Test Sig 2",
            "score": 0,
        },
    ]

    section = hatching_result_instance._build_sig_section(signatures=hatching_sigs)

    assert section is not None
    assert section.title_text == "Signatures"
    assert section.body_format == BODY_FORMAT.TEXT
    assert section.body is None
    assert section.heuristic is None
    assert section.tags == {}

    # Validate all sub-sections present.
    assert len(section.subsections) == 2

    expected_subs = [
        "Signature: Test Sig 1",
        "Signature: Test Sig 2",
    ]

    for sub_sec in section.subsections:
        # log.warning(sub_sec.title_text)
        assert sub_sec.title_text in expected_subs

    # validate sigs added to the ontres properly
    ontres = hatching_result_instance.ontres

    sig_primitives = [sig.as_primitives() for sig in ontres.signatures]
    # log.warning(sig_primitives)
    assert sig_primitives == [
        {
            "objectid": {
                "tag": "CUCKOO.Test Sig 1",
                "ontology_id": "signature_5OqJRcAIh2lvwvmMVgjM0P",
                "service_name": "HATCHING",
                "guid": None,
                "treeid": None,
                "processtree": None,
                "time_observed": None,
                "session": None,
            },
            "name": "Test Sig 1",
            "type": "CUCKOO",
            "attributes": [],
            "classification": "TLP:C",
            "attacks": [
                {
                    "attack_id": "T1006",
                    "pattern": "Direct Volume Access",
                    "categories": ["defense-evasion"],
                },
                {
                    "attack_id": "T1552.001",
                    "pattern": "Credentials In Files",
                    "categories": ["credential-access"],
                },
            ],
            "actors": [],
            "malware_families": ["test"],
        },
        {
            "objectid": {
                "tag": "CUCKOO.Test Sig 2",
                "ontology_id": "signature_zDSL8muqbwXqwJvIr3I3L",
                "service_name": "HATCHING",
                "guid": None,
                "treeid": None,
                "processtree": None,
                "time_observed": None,
                "session": None,
            },
            "name": "Test Sig 2",
            "type": "CUCKOO",
            "attributes": [],
            "classification": "TLP:C",
            "attacks": [],
            "actors": [],
            "malware_families": [],
        },
    ]


def test_returns_none(
    hatching_result_instance: hatching_result_instance,
):
    """Validate nothing is returned when there are no hatching sigs in the input."""
    hatching_sigs = []
    section = hatching_result_instance._build_sig_section(signatures=hatching_sigs)
    assert section is None

    hatching_sigs = None
    section = hatching_result_instance._build_sig_section(signatures=hatching_sigs)
    assert section is None

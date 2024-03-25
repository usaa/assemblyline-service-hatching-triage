import pytest
import json
import logging as log

from assemblyline_v4_service.common.result import BODY_FORMAT
from .utils import hatching_result_instance


def test_build_sig_sub_section(
    hatching_result_instance: hatching_result_instance,
):
    """
    Validate the happy path. This validates both static and dynamic report scenarios.

    A ResultKeyValueSection is created with the appropriate key-values, associated heuristic, and tags.
    """

    # Extract from static or dynamic analysis report: .signatures[]
    hatching_sigs = [
        {
            "name": "Ramnit family",
            "score": 10,
            "tags": ["family:ramnit"],
            "ttp": ["T1005", "T1552.001"],
            "desc": "test description",
        },
    ]
    # build the expected sigs input
    sigs = hatching_result_instance._process_sigs(hatching_sigs=hatching_sigs)

    section = hatching_result_instance._build_sig_sub_section(
        ontres_sig=sigs[0].get("ontres_sig"), hatching_sig=sigs[0].get("hatching_sig")
    )

    assert section is not None
    assert section.title_text == "Signature: Ramnit family"
    assert section.body_format == BODY_FORMAT.KEY_VALUE

    # log.warning(section.body)
    assert json.loads(section.body) == {
        "Description": "test description",
        "Score": "10 of 10",
    }

    assert section.heuristic.heur_id == 300
    assert section.heuristic.attack_ids == ["T1005", "T1552.001"]
    assert section.heuristic.signatures == {"Ramnit family": 1}
    assert section.heuristic.score == 1000

    # log.warning(section.tags)
    assert section.tags == {"dynamic.signature.family": ["ramnit"]}
    assert len(section.subsections) == 0


def test_when_val_in_body_but_no_tags_generated(
    hatching_result_instance: hatching_result_instance,
):
    """Validate that a Result when minimal information is available for the sig.

    A ResultKeyValueSection is created with the appropriate key-values, associated heuristic, and NO tags.
    """

    # Extract from static or dynamic analysis report: .signatures[]
    hatching_sigs = [
        {
            "name": "Generic Sig",
        },
    ]
    # build the expected sigs input
    sigs = hatching_result_instance._process_sigs(hatching_sigs=hatching_sigs)

    section = hatching_result_instance._build_sig_sub_section(
        ontres_sig=sigs[0].get("ontres_sig"), hatching_sig=sigs[0].get("hatching_sig")
    )

    assert section is not None
    assert section.title_text == "Signature: Generic Sig"
    assert section.body_format == BODY_FORMAT.KEY_VALUE

    # log.warning(section.body)
    assert json.loads(section.body) == {
        "Description": "No description for signature.",
        "Score": "No Score",
    }

    assert section.heuristic.heur_id == 300
    assert section.heuristic.attack_ids == []
    assert section.heuristic.signatures == {"Generic Sig": 1}
    assert section.heuristic.score == 0

    # log.warning(section.tags)
    assert section.tags == {}
    assert len(section.subsections) == 0


def test_tag_in_safelist_not_generated(
    hatching_result_instance: hatching_result_instance,
):
    """Validate that when a specific tag is in the safelist, it does not get generated when it otherwise would."""

    # Extract from static or dynamic analysis report: .signatures[]
    hatching_sigs = [
        {
            "name": "Test family",
            "score": 6,
            "tags": ["family:test"],
            "desc": "test description",
        },
    ]
    # build the expected sigs input
    sigs = hatching_result_instance._process_sigs(hatching_sigs=hatching_sigs)

    hatching_result_instance.safelist = {
        "match": {"dynamic.signature.family": ["test"]}
    }
    section = hatching_result_instance._build_sig_sub_section(
        ontres_sig=sigs[0].get("ontres_sig"), hatching_sig=sigs[0].get("hatching_sig")
    )

    assert section is not None
    assert section.title_text == "Signature: Test family"
    assert section.body_format == BODY_FORMAT.KEY_VALUE

    # log.warning(section.body)
    assert json.loads(section.body) == {
        "Description": "test description",
        "Score": "6 of 10",
    }

    assert section.heuristic.heur_id == 300
    assert section.heuristic.attack_ids == []
    assert section.heuristic.signatures == {"Test family": 1}
    assert section.heuristic.score == 600

    # log.warning(section.tags)
    assert section.tags == {}
    assert len(section.subsections) == 0


def test_returns_none(
    hatching_result_instance: hatching_result_instance,
):
    """Validate the Result is returned as None when no data presented."""

    section = hatching_result_instance._build_sig_sub_section(
        ontres_sig=None, hatching_sig=None
    )
    assert section is None

    section = hatching_result_instance._build_sig_sub_section(
        ontres_sig=None, hatching_sig={}
    )
    assert section is None

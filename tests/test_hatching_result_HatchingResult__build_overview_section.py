import pytest
import json
import logging as log

from assemblyline_v4_service.common.result import BODY_FORMAT
from .utils import hatching_result_instance


def test_build_overview_section(hatching_result_instance: hatching_result_instance):
    """Validate link ResultSection created properly."""

    # simplified view of results overview hatching api results
    overview = {
        "sample": {
            "score": 10,
            "created": "2023-08-15T12:46:41Z",
            "completed": "2023-08-15T12:47:18Z",
        },
        "tasks": [
            {
                "kind": "behavioral",
                "task_name": "vm-profile-win",
            },
            {
                "kind": "static",
            },
        ],
        "analysis": {
            "score": 10,
        },
    }

    section = hatching_result_instance._build_overview_section(overview=overview)

    assert section.title_text == "Results Overview"
    assert section.body_format == BODY_FORMAT.KEY_VALUE

    body = section.body
    # log.warning(json.loads(body))
    assert json.loads(body) == {
        "Overall Score": "10 of 10",
        "Sample ID": "230815-xxxyyyzzz1",
        "Duration": "37 seconds",
        "VM Profile(s)": "vm-profile-win",
    }

    assert section.heuristic.heur_id == 2
    assert section.heuristic.attack_ids == []
    assert section.heuristic.signatures == {}
    assert section.heuristic.score == 1000

    assert section.tags == {}
    assert len(section.subsections) == 0


def test_unexpected_inputs(hatching_result_instance: hatching_result_instance):
    """Validate link ResultSection created properly even with unexpected inputs."""

    # simplified view of results overview hatching api results
    overview = {
        "sample": {
            "created": "2023-08-15T12:46:41Z",
            "completed": "2023-08-15T12:47:18Z",
        },
        "tasks": [
            {
                "kind": "static",
            },
        ],
    }

    section = hatching_result_instance._build_overview_section(overview=overview)

    assert section.title_text == "Results Overview"
    assert section.body_format == BODY_FORMAT.KEY_VALUE

    body = section.body
    # log.warning(json.loads(body))
    assert json.loads(body) == {
        "Overall Score": "None of 10",
        "Sample ID": "230815-xxxyyyzzz1",
        "Duration": "37 seconds",
        "VM Profile(s)": "",
    }

    assert section.heuristic is None
    assert section.tags == {}
    assert len(section.subsections) == 0


def test_returns_none(hatching_result_instance: hatching_result_instance):
    """Validate ResultSection not created when data is missing"""

    overview = {}
    section = hatching_result_instance._build_overview_section(overview=overview)
    assert section is None

    overview = None
    section = hatching_result_instance._build_overview_section(overview=overview)
    assert section is None

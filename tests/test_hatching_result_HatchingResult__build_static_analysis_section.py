import pytest
import json
import logging as log

from assemblyline_v4_service.common.result import BODY_FORMAT
from .utils import hatching_result_instance, find_result_section


def test_build_static_analysis_section(
    hatching_result_instance: hatching_result_instance,
):
    """Validate the Static Analysis ResultsSection and sub-sections are present given the relevant data.
    Expected Signatures and Extracted Items sub-sections.
    """
    # abbreviated of of the hatching api results for static analysis
    static_report = {
        "signatures": [
            {
                "name": "Test Sig 1",
                "score": 10,
                "tags": ["family:test"],
                "ttp": ["T1006", "T1552.001"],
                "desc": "test description 1",
            },
        ],
        "extracted": [
            {
                "config": {
                    "c2": ["1.3.3.7:4433"],
                }
            },
        ],
    }

    section = hatching_result_instance._build_static_analysis_section(
        static_report=static_report
    )
    assert section.title_text == "Static Analysis"
    assert section.body_format == BODY_FORMAT.TEXT
    assert section.body is None
    assert section.heuristic is None
    assert section.tags == {}

    assert len(section.subsections) == 2
    #
    # Signatures sub-section
    sub_section = find_result_section(section.subsections, "Signatures")
    assert sub_section is not None
    assert sub_section.title_text == "Signatures"

    #
    # Extracted Items sub-section
    sub_section = find_result_section(section.subsections, "Extracted Items")
    assert sub_section is not None
    assert sub_section.title_text == "Extracted Items"


def test_with_minimal_data(
    hatching_result_instance: hatching_result_instance,
):
    """Validate the Static Analysis ResultsSection and sub-section are present given the relevant data.

    Expected Extracted Items sub-section only.
    """
    # abbreviated of of the hatching api results for static analysis
    static_report = {
        "extracted": [
            {
                "config": {
                    "c2": ["1.3.3.7:4433"],
                }
            },
        ],
    }

    section = hatching_result_instance._build_static_analysis_section(
        static_report=static_report
    )
    assert section.title_text == "Static Analysis"
    assert section.body_format == BODY_FORMAT.TEXT
    assert section.body is None
    assert section.heuristic is None
    assert section.tags == {}

    assert len(section.subsections) == 1

    #
    # Extracted Items sub-section
    sub_section = find_result_section(section.subsections, "Extracted Items")
    assert sub_section is not None
    assert sub_section.title_text == "Extracted Items"


def test_when_no_static_report(
    hatching_result_instance: hatching_result_instance,
):
    """Validate None is returned for various scenarios where no static report sections should be generated."""
    #
    # Scenario 1 - static report with no signatures or extracted items
    # abbreviated of of the hatching api results for static analysis
    static_report = {
        "sample": {
            "sample": "230922-1112223334",
            "kind": "file",
            "size": 58368,
        },
    }
    section = hatching_result_instance._build_static_analysis_section(
        static_report=static_report
    )
    assert section is None

    #
    # Scenario 2 - no report at all
    static_report = {}
    section = hatching_result_instance._build_static_analysis_section(
        static_report=static_report
    )
    assert section is None

    static_report = None
    section = hatching_result_instance._build_static_analysis_section(
        static_report=static_report
    )
    assert section is None

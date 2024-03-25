import pytest
import json
import logging as log

from assemblyline_v4_service.common.result import BODY_FORMAT
from .utils import hatching_result_instance


def test_build_dynamic_result_info_section(
    hatching_result_instance: hatching_result_instance,
):
    """Validate the ResultSection is created as expected for standard expected data.

    Expected ResultKeyValueSection and updated ontres for the Sandbox instance.
    """

    # Abbreviated version of a triage report
    triage_rpt = {
        "analysis": {
            "score": 1,
            "submitted": "2023-09-22T21:47:33Z",
            "reported": "2023-09-22T21:48:43Z",
            "platform": "windows10-2004_x64",
        },
        "task_name": "test-task",
        "version": "0.3.0",
    }
    section = hatching_result_instance._build_dynamic_result_info_section(
        triage_rpt=triage_rpt
    )

    assert section is not None
    assert section.title_text == "Analysis Information"
    assert section.body_format == BODY_FORMAT.KEY_VALUE

    # log.warning(section.body)
    assert json.loads(section.body) == {
        "Score": "1 of 10",
        "Task Name": "test-task",
        "Platform": "windows10-2004_x64",
        "Duration": "70 seconds",
    }

    assert section.heuristic is None
    # log.warning(section.tags)
    assert section.tags == {}

    # Validate ontres updated for the sandbox entry
    assert len(hatching_result_instance.ontres.sandboxes) == 1


def test_with_missing_data(
    hatching_result_instance: hatching_result_instance,
):
    """Validate the ResultSection is still created when some data elements are missing.

    The ontres will not be created when the information is not available.
    Validate the ResultSection is created as expected for standard expected data.

    Expected ResultKeyValueSection and updated ontres for the Sandbox instance.
    """

    # Abbreviated version of a triage report
    triage_rpt = {
        "analysis": {
            "score": 1,
            "submitted": "2023-09-22T21:47:33Z",
            "reported": "2023-09-22T21:48:43Z",
            # "platform": "windows10-2004_x64",
        },
        "task_name": "test-task",
        # "version": "0.3.0",
    }
    section = hatching_result_instance._build_dynamic_result_info_section(
        triage_rpt=triage_rpt
    )

    assert section is not None
    assert section.title_text == "Analysis Information"
    assert section.body_format == BODY_FORMAT.KEY_VALUE

    # log.warning(section.body)
    assert json.loads(section.body) == {
        "Score": "1 of 10",
        "Task Name": "test-task",
        "Platform": None,
        "Duration": "70 seconds",
    }

    assert section.heuristic is None
    # log.warning(section.tags)
    assert section.tags == {}
    assert len(section.subsections) == 0

    # Validate ontres not added since missing data
    assert len(hatching_result_instance.ontres.sandboxes) == 0


def test_returns_none(
    hatching_result_instance: hatching_result_instance,
):
    """Validate the Result is returned as None when no data presented."""

    triage_rpt = {}
    section = hatching_result_instance._build_dynamic_result_info_section(
        triage_rpt=triage_rpt
    )
    assert section is None

    triage_rpt = None
    section = hatching_result_instance._build_dynamic_result_info_section(
        triage_rpt=triage_rpt
    )
    assert section is None

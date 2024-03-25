import pytest
import json
import logging as log
import re

from unittest import mock
from unittest.mock import patch
from unittest.mock import MagicMock, PropertyMock

from .utils import hatching_service_instance

from hatching.hatching import MissingParamException


def test_get_hatching_submission_results(hatching_service_instance):
    """Validate the API results are aggregated and structured appropriately."""

    # Mock overview results
    overview = {
        "sample": {
            "score": 1,
            "created": "2023-08-15T12:46:41Z",
            "completed": "2023-08-15T12:47:18Z",
        },
        "tasks": [
            {
                "kind": "behavioral",
                "name": "behavioral1",
                "task_name": "vm-profile-win",
            },
            {
                "kind": "static",
            },
        ],
    }
    hatching_service_instance._get_hatching_submission_results_overview = MagicMock(
        return_value=overview
    )

    # Mock static results
    static_report = {
        "signatures": [],
        "extracted": [],
    }
    hatching_service_instance._get_hatching_submission_results_static_report = (
        MagicMock(return_value=static_report)
    )

    # Mock triage report results
    triage_rpt = {
        "analysis": {
            "platform": "windows10-2004_x64",
        },
        "extracted": [],
        "network": {},
        "signatures": [],
        "task_name": "vm-profile-win",
        "version": "0.3.0",
    }
    hatching_service_instance._get_hatching_submission_results_triage_report = (
        MagicMock(return_value=triage_rpt)
    )

    results = hatching_service_instance._get_hatching_submission_results(1)
    # log.warning(results)

    # validate structure is returned as expected
    assert results == {
        "overview": {
            "sample": {
                "score": 1,
                "created": "2023-08-15T12:46:41Z",
                "completed": "2023-08-15T12:47:18Z",
            },
            "tasks": [
                {
                    "kind": "behavioral",
                    "name": "behavioral1",
                    "task_name": "vm-profile-win",
                },
                {"kind": "static"},
            ],
        },
        "static_report": {"signatures": [], "extracted": []},
        "triage_reports": [
            {
                "analysis": {"platform": "windows10-2004_x64"},
                "extracted": [],
                "network": {},
                "signatures": [],
                "task_name": "behavioral1",
                "version": "0.3.0",
            }
        ],
    }
    # validate prop is added
    assert results.get("triage_reports")[0].get("task_name") == "behavioral1"


def test_when_missing_triage_reports(hatching_service_instance):
    """Validate results for scenario when triage reports are not found."""

    # Mock overview results
    overview = {
        "sample": {
            "score": 1,
            "created": "2023-08-15T12:46:41Z",
            "completed": "2023-08-15T12:47:18Z",
        },
        "tasks": [
            {
                "kind": "behavioral",
                "name": "behavioral1",
                "task_name": "vm-profile-win",
            },
            {
                "kind": "static",
            },
        ],
    }
    hatching_service_instance._get_hatching_submission_results_overview = MagicMock(
        return_value=overview
    )

    # Mock static results
    static_report = {
        "signatures": [],
        "extracted": [],
    }
    hatching_service_instance._get_hatching_submission_results_static_report = (
        MagicMock(return_value=static_report)
    )

    # Mock triage report results
    triage_rpt = None

    hatching_service_instance._get_hatching_submission_results_triage_report = (
        MagicMock(return_value=triage_rpt)
    )

    results = hatching_service_instance._get_hatching_submission_results(1)
    # log.warning(results)

    # validate structure is returned as expected when no triage reports found
    assert results == {
        "overview": {
            "sample": {
                "score": 1,
                "created": "2023-08-15T12:46:41Z",
                "completed": "2023-08-15T12:47:18Z",
            },
            "tasks": [
                {
                    "kind": "behavioral",
                    "name": "behavioral1",
                    "task_name": "vm-profile-win",
                },
                {"kind": "static"},
            ],
        },
        "static_report": {"signatures": [], "extracted": []},
        "triage_reports": [],
    }


def test_raises_excep_when_missing_param(hatching_service_instance):
    """Validate exception raised when sample_id not passed in."""

    with pytest.raises(
        MissingParamException,
        match=re.escape("sample_id was not specified."),
    ):
        results = hatching_service_instance._get_hatching_submission_results(None)

import pytest
import json
import logging as log

from unittest import mock
from unittest.mock import patch
from unittest.mock import MagicMock, PropertyMock

from .utils import hatching_service_instance


def test_build_dumped_artifacts(hatching_service_instance):
    """Validate the artifacts list object is created properly when a single triage report is processed."""

    # abbreviated hatching api results for triage reports
    triage_reports = [
        {
            "sample": {"id": "230818-aaabbbcccd"},
            "dumped": [
                {
                    "name": "files/test1.dat",
                    "origin": "imgload",
                },
                {
                    "name": "memory/001.dmp",
                    "origin": "dotnet64",
                },
            ],
            "task_name": "behavioral1",
        },
    ]
    analyze_extracted_memory_dumps = True
    artifacts = hatching_service_instance._build_dumped_artifacts(
        triage_reports=triage_reports,
        analyze_extracted_memory_dumps=analyze_extracted_memory_dumps,
    )
    # log.warning(artifacts)
    assert artifacts == [
        {
            "name": "files/test1.dat",
            "path": None,
            "description": "files/test1.dat",
            "to_be_extracted": True,
            "hatching_api": {
                "sample_id": "230818-aaabbbcccd",
                "task_name": "behavioral1",
                "resource_name": "files/test1.dat",
            },
        },
        {
            "name": "memory/001.dmp",
            "path": None,
            "description": "memory/001.dmp",
            "to_be_extracted": True,
            "hatching_api": {
                "sample_id": "230818-aaabbbcccd",
                "task_name": "behavioral1",
                "resource_name": "memory/001.dmp",
            },
        },
        {
            "name": "behavioral1.pcapng",
            "path": None,
            "description": "behavioral1.pcapng",
            "to_be_extracted": True,
            "hatching_api": {
                "sample_id": "230818-aaabbbcccd",
                "task_name": "behavioral1",
                "resource_name": "dump.pcapng",
            },
        },
    ]


def test_build_dumped_artifacts_with_multiple_reports(hatching_service_instance):
    """Validate the artifacts list object is created properly when a multiple triage report is processed."""

    # abbreviated hatching api results for triage reports
    triage_reports = [
        {
            "sample": {"id": "230818-aaabbbcccd"},
            "dumped": [
                {
                    "name": "files/test1.dat",
                    "origin": "imgload",
                },
            ],
            "task_name": "behavioral1",
        },
        {
            "sample": {"id": "230818-aaabbbcccd"},
            "dumped": [
                # Repeat, so should not be duplicated
                {
                    "name": "files/test1.dat",
                    "origin": "imgload",
                },
                {
                    "name": "memory/002.dmp",
                    "origin": "dotnet64",
                },
            ],
            "task_name": "behavioral2",
        },
    ]
    analyze_extracted_memory_dumps = True
    artifacts = hatching_service_instance._build_dumped_artifacts(
        triage_reports=triage_reports,
        analyze_extracted_memory_dumps=analyze_extracted_memory_dumps,
    )
    # log.warning(artifacts)
    assert artifacts == [
        {
            "name": "files/test1.dat",
            "path": None,
            "description": "files/test1.dat",
            "to_be_extracted": True,
            "hatching_api": {
                "sample_id": "230818-aaabbbcccd",
                "task_name": "behavioral1",
                "resource_name": "files/test1.dat",
            },
        },
        {
            "name": "behavioral1.pcapng",
            "path": None,
            "description": "behavioral1.pcapng",
            "to_be_extracted": True,
            "hatching_api": {
                "sample_id": "230818-aaabbbcccd",
                "task_name": "behavioral1",
                "resource_name": "dump.pcapng",
            },
        },
        {
            "name": "files/test1.dat",
            "path": None,
            "description": "files/test1.dat",
            "to_be_extracted": True,
            "hatching_api": {
                "sample_id": "230818-aaabbbcccd",
                "task_name": "behavioral2",
                "resource_name": "files/test1.dat",
            },
        },
        {
            "name": "memory/002.dmp",
            "path": None,
            "description": "memory/002.dmp",
            "to_be_extracted": True,
            "hatching_api": {
                "sample_id": "230818-aaabbbcccd",
                "task_name": "behavioral2",
                "resource_name": "memory/002.dmp",
            },
        },
        {
            "name": "behavioral2.pcapng",
            "path": None,
            "description": "behavioral2.pcapng",
            "to_be_extracted": True,
            "hatching_api": {
                "sample_id": "230818-aaabbbcccd",
                "task_name": "behavioral2",
                "resource_name": "dump.pcapng",
            },
        },
    ]


def test_when_files_excluded(hatching_service_instance):
    """Validate both dups are excluded and memory dumps not eligible for extraction."""

    # abbreviated hatching api results for triage reports
    triage_reports = [
        {
            "sample": {"id": "230818-aaabbbcccd"},
            "dumped": [
                {
                    "name": "files/test1.dat",
                    "origin": "imgload",
                },
                # duplicate item
                {
                    "name": "files/test1.dat",
                    "origin": "imgload",
                },
                # not eligible for extract. Output to_be_extracted will be False
                {
                    "name": "memory/001.dmp",
                    "origin": "exception",
                },
            ],
            "task_name": "behavioral1",
        },
    ]
    analyze_extracted_memory_dumps = True
    artifacts = hatching_service_instance._build_dumped_artifacts(
        triage_reports=triage_reports,
        analyze_extracted_memory_dumps=analyze_extracted_memory_dumps,
    )
    # log.warning(artifacts)
    assert artifacts == [
        {
            "name": "files/test1.dat",
            "path": None,
            "description": "files/test1.dat",
            "to_be_extracted": True,
            "hatching_api": {
                "sample_id": "230818-aaabbbcccd",
                "task_name": "behavioral1",
                "resource_name": "files/test1.dat",
            },
        },
        {
            "name": "memory/001.dmp",
            "path": None,
            "description": "memory/001.dmp",
            "to_be_extracted": False,
            "hatching_api": {
                "sample_id": "230818-aaabbbcccd",
                "task_name": "behavioral1",
                "resource_name": "memory/001.dmp",
            },
        },
        {
            "name": "behavioral1.pcapng",
            "path": None,
            "description": "behavioral1.pcapng",
            "to_be_extracted": True,
            "hatching_api": {
                "sample_id": "230818-aaabbbcccd",
                "task_name": "behavioral1",
                "resource_name": "dump.pcapng",
            },
        },
    ]


def test_null_inputs(hatching_service_instance):
    """Validate no artifacts returned when null inputs for the triage reports."""

    triage_reports = []
    analyze_extracted_memory_dumps = True
    artifacts = hatching_service_instance._build_dumped_artifacts(
        triage_reports=triage_reports,
        analyze_extracted_memory_dumps=analyze_extracted_memory_dumps,
    )
    assert artifacts == []

    triage_reports = None
    analyze_extracted_memory_dumps = True
    artifacts = hatching_service_instance._build_dumped_artifacts(
        triage_reports=triage_reports,
        analyze_extracted_memory_dumps=analyze_extracted_memory_dumps,
    )
    assert artifacts == []

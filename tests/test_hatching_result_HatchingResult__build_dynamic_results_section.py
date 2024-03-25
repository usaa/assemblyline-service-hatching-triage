import pytest
import json
import logging as log

from assemblyline_v4_service.common.result import BODY_FORMAT
from .utils import hatching_result_instance, find_result_section


def test_build_dynamic_results_section(
    hatching_result_instance: hatching_result_instance,
):
    """Validate the Dynamic Analysis Results Section and all sub-sections are created given the relevant data.

    Expected Analysis Info, Signatures, Extracted Items, and Network sub-sections.
    """
    # abbreviated of of the hatching api results for a dynamic analysis triage report
    triage_rpt = {
        "analysis": {
            "score": 1,
            "submitted": "2023-09-22T21:47:33Z",
            "reported": "2023-09-22T21:48:43Z",
            "platform": "windows10-2004_x64",
        },
        "extracted": [
            {
                "config": {
                    "c2": ["1.3.3.7:4433"],
                }
            },
        ],
        "network": {
            "requests": [
                {
                    "flow": 26,
                    "dns_request": {
                        "domains": ["test.local"],
                    },
                },
                {
                    "flow": 26,
                    "dns_response": {
                        "domains": ["test.local"],
                        "ip": ["1.1.1.1", "1.1.1.2"],
                    },
                },
                {
                    "flow": 17,
                    "index": 1,
                    "http_request": {
                        "method": "POST",
                        "url": "http://1.1.1.1/",
                        "request": "POST / HTTP/1.1",
                        "headers": [
                            "Accept: */*",
                            "Content-Type: application/x-www-form-urlencoded; charset=utf-8",
                            "User-Agent: moz",
                            "Host: 1.1.1.1",
                        ],
                    },
                },
                {
                    "flow": 17,
                    "index": 1,
                    "http_response": {"status": "200", "response": "HTTP/1.0 200 OK"},
                },
            ],
            "flows": [
                {
                    "id": 3,
                    "src": "10.127.0.30:64935",
                    "dst": "1.1.1.1:80",
                    "protocols": ["http"],
                    "domain": "1.1.1.1",
                },
            ],
        },
        "processes": [
            {
                "procid": 27,
                "procid_parent": 11,
                "pid": 2352,
                "ppid": 1356,
                "cmd": '"C:\\Users\\Admin\\AppData\\Local\\Temp\\sample.exe"',
                "image": "C:\\Users\\Admin\\AppData\\Local\\Temp\\sample.exe",
                "orig": False,
                "started": 452,
                "terminated": 1388,
            },
            {
                "procid": 28,
                "procid_parent": 27,
                "pid": 924,
                "ppid": 2352,
                "cmd": "c:\\windows\\resources\\themes\\explorer.exe",
                "image": "\\??\\c:\\windows\\resources\\themes\\explorer.exe",
                "orig": False,
                "started": 764,
            },
        ],
        "signatures": [
            {
                "name": "Test Sig 1",
                "score": 10,
                "tags": ["family:test"],
                "ttp": ["T1006", "T1552.001"],
                "desc": "test description 1",
            },
        ],
        "task_name": "test-task",
        "version": "0.3.0",
    }

    section = hatching_result_instance._build_dynamic_results_sections(
        triage_rpt=triage_rpt
    )
    assert (
        section.title_text
        == f"Dynamic Analysis Platform: {triage_rpt.get('analysis').get('platform')}"
    )
    assert section.body_format == BODY_FORMAT.TEXT
    assert section.body is None
    assert section.heuristic is None
    assert section.tags == {}

    # log.warning(section.subsections)
    assert len(section.subsections) == 5
    #
    # Info sub-section
    sub_section = find_result_section(section.subsections, "Analysis Information")
    assert sub_section is not None
    assert sub_section.title_text == "Analysis Information"
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

    #
    # Network sub-section
    sub_section = find_result_section(section.subsections, "Network")
    assert sub_section is not None
    assert sub_section.title_text == "Network"

    #
    # Processes sub-section
    sub_section = find_result_section(section.subsections, "Spawned Process Tree")
    assert sub_section is not None
    assert sub_section.title_text == "Spawned Process Tree"


def test_minimal_data(
    hatching_result_instance: hatching_result_instance,
):
    """
    Validate the Dynamic Analysis Results Section and only the Analysis Info sub-section is present.
    """
    # abbreviated of of the hatching api results for a dynamic analysis triage report
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

    section = hatching_result_instance._build_dynamic_results_sections(
        triage_rpt=triage_rpt
    )
    assert (
        section.title_text
        == f"Dynamic Analysis Platform: {triage_rpt.get('analysis').get('platform')}"
    )
    assert section.body_format == BODY_FORMAT.TEXT
    assert section.body is None
    assert section.heuristic is None
    assert section.tags == {}

    # log.warning(section.subsections)
    assert len(section.subsections) == 1
    #
    # Info sub-section
    sub_section = find_result_section(section.subsections, "Analysis Information")
    assert sub_section is not None
    assert sub_section.title_text == "Analysis Information"


def test_when_no_triage_rpt(
    hatching_result_instance: hatching_result_instance,
):
    """Validate None is returned for various scenarios where no dynamic report data is present."""
    triage_rpt = {}
    section = hatching_result_instance._build_dynamic_results_sections(
        triage_rpt=triage_rpt
    )
    assert section is None

    triage_rpt = None
    section = hatching_result_instance._build_dynamic_results_sections(
        triage_rpt=triage_rpt
    )
    assert section is None

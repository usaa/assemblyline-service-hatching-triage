"""The detailed testing of each of the sub-sections is handled with the unit tests for those various methods."""

import pytest
import json
import logging as log

from assemblyline_v4_service.common.result import BODY_FORMAT
from .utils import hatching_result_instance, find_result_section


def test_build_network_section(
    hatching_result_instance: hatching_result_instance,
):
    """Validate that all network sub-sections are present when all data is present.

    Expects 3 sub-sections: DNS, HTTP, Network Flows
    """

    # Abbreviated example data created from a dynamic analysis triage report: .network key
    hatching_network = {
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
    }

    section = hatching_result_instance._build_network_section(
        hatching_network=hatching_network
    )

    # Validate main section
    assert section is not None
    assert section.title_text == "Network"
    assert section.body_format == BODY_FORMAT.TEXT
    # log.warning(section.body)
    assert section.body is None
    assert section.heuristic is None
    # log.warning(section.tags)
    assert section.tags == {}

    assert len(section.subsections) == 3

    #
    # DNS Resolutions sub-section
    sub_section = find_result_section(section.subsections, "DNS Resolutions")
    assert sub_section is not None
    assert sub_section.title_text == "DNS Resolutions"

    #
    # HTTP Traffic sub-section
    sub_section = find_result_section(section.subsections, "HTTP Traffic")
    assert sub_section is not None
    assert sub_section.title_text == "HTTP Traffic"

    #
    # Network Flows sub-section
    sub_section = find_result_section(section.subsections, "Network Flows")
    assert sub_section is not None
    assert sub_section.title_text == "Network Flows"


def test_sections_show_up_as_necessary(
    hatching_result_instance: hatching_result_instance,
):
    """Validate various data input scenarios to make sure that each sub-section only shows when it has the appropriate
    data to cause it to show.

    3 Scenarios to make sure that only that sub-section shows instead of all 3 when only the data for that sub-section
    is present in the input.
    """

    #
    # Scenario 1 - Only the dns sub-section is present
    hatching_network = {
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
        ]
    }
    section = hatching_result_instance._build_network_section(
        hatching_network=hatching_network
    )
    # Validate main section
    assert section is not None
    assert section.title_text == "Network"
    assert len(section.subsections) == 1
    #
    # DNS Resolutions sub-section
    sub_section = find_result_section(section.subsections, "DNS Resolutions")
    assert sub_section is not None
    assert sub_section.title_text == "DNS Resolutions"

    #
    # Scenario 2 - Only the http sub-section is present
    hatching_network = {
        "requests": [
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
    }
    section = hatching_result_instance._build_network_section(
        hatching_network=hatching_network
    )
    # Validate main section
    assert section is not None
    assert section.title_text == "Network"
    assert len(section.subsections) == 1
    #
    # HTTP Traffic sub-section
    sub_section = find_result_section(section.subsections, "HTTP Traffic")
    assert sub_section is not None
    assert sub_section.title_text == "HTTP Traffic"

    #
    # Scenario 3 - Only the network-flows sub-section is present
    hatching_network = {
        "flows": [
            {
                "id": 3,
                "src": "10.127.0.30:64935",
                "dst": "1.1.1.1:80",
                "protocols": ["http"],
                "domain": "1.1.1.1",
            },
        ],
    }
    section = hatching_result_instance._build_network_section(
        hatching_network=hatching_network
    )
    # Validate main section
    assert section is not None
    assert section.title_text == "Network"
    assert len(section.subsections) == 1
    #
    # Network Flows sub-section
    sub_section = find_result_section(section.subsections, "Network Flows")
    assert sub_section is not None
    assert sub_section.title_text == "Network Flows"


def test_build_network_section_filtered(
    hatching_result_instance: hatching_result_instance,
):
    """Validate that with filtered-flow-ids logic works.

    The dns traffic in this test will be safelisted which will cause the flow-id to be filtered in subsequent sections.
    In this test case, the dns-sub-section will not produce results since it's single request is filtered.
    The network-flows sub-section will not subsequently create a ResultsSection since the associated flow-id is now
    considered filtered.

    Expects 1 sub-sections: HTTP
    """

    # Abbreviated example data created from a dynamic analysis triage report: .network key
    hatching_network = {
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
                "id": 26,
                "src": "10.127.0.30:64935",
                "dst": "8.8.8.8:53",
                "protocols": ["dns"],
            },
        ],
    }

    hatching_result_instance.safelist = {
        "match": {"network.dynamic.domain": ["test.local"]}
    }
    section = hatching_result_instance._build_network_section(
        hatching_network=hatching_network
    )

    # Validate main section
    assert section is not None
    assert section.title_text == "Network"
    assert section.body_format == BODY_FORMAT.TEXT
    # log.warning(section.body)
    assert section.body is None
    assert section.heuristic is None
    # log.warning(section.tags)
    assert section.tags == {}

    # log.warning(section.subsections)
    assert len(section.subsections) == 1

    #
    # HTTP Traffic sub-section
    sub_section = find_result_section(section.subsections, "HTTP Traffic")
    assert sub_section is not None
    assert sub_section.title_text == "HTTP Traffic"


def test_returns_none(
    hatching_result_instance: hatching_result_instance,
):
    """Validate the Result is returned as None when no data presented."""

    hatching_network = {}
    section = hatching_result_instance._build_network_section(
        hatching_network=hatching_network
    )
    assert section is None

    hatching_network = None
    section = hatching_result_instance._build_network_section(
        hatching_network=hatching_network
    )
    assert section is None

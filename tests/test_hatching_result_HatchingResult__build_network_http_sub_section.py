import pytest
import json
import logging as log

from assemblyline_v4_service.common.result import BODY_FORMAT
from .utils import hatching_result_instance, find_result_section


def test_build_network_http_sub_section(
    hatching_result_instance: hatching_result_instance,
):
    """Validate the http ResultSection is created properly for basic input with an http-request.

    Expects a section with multiple sub-sections and associated tags.
    """

    # http traffic dict - response from _process_http_traffic()
    http_traff = {
        17: {
            "http_request": {
                "method": "POST",
                "url": "http://1.1.1.1/test",
                "request": "POST / HTTP/1.1",
                "headers": {"user-agent": "moz", "host": "1.1.1.1"},
            },
            "http_response": {"status": "200", "response": "HTTP/1.0 200 OK"},
        }
    }
    filtered_flow_ids = set()
    section = hatching_result_instance._build_network_http_sub_section(
        http_traffic=http_traff, filtered_flow_ids=filtered_flow_ids
    )

    # Validate main section
    assert section is not None
    assert section.title_text == "HTTP Traffic"
    assert section.body_format == BODY_FORMAT.TEXT
    # log.warning(section.body)
    assert section.body is None
    assert section.heuristic is None
    assert section.tags == {}

    #
    # Validate each sub-section
    #
    assert len(section.subsections) == 2

    #
    # Extracted URIs sub-section
    sub_section = find_result_section(section.subsections, "Extracted URIs")
    assert sub_section is not None
    assert sub_section.title_text == "Extracted URIs"
    assert sub_section.body_format == BODY_FORMAT.TABLE
    # log.warning(sub_section.body)
    assert json.loads(sub_section.body) == [{"uri": "http://1.1.1.1/test"}]
    assert sub_section.heuristic is None
    # log.warning(sub_section.tags)
    assert sub_section.tags == {
        "network.dynamic.ip": ["1.1.1.1"],
        "network.dynamic.uri": ["http://1.1.1.1/test"],
        "network.dynamic.uri_path": ["/test"],
    }

    #
    # Extracted User Agents from Headers
    sub_section = find_result_section(
        section.subsections, "Extracted User Agents from Headers"
    )
    assert sub_section is not None
    assert sub_section.title_text == "Extracted User Agents from Headers"
    assert sub_section.body_format == BODY_FORMAT.TABLE
    # log.warning(sub_section.body)
    assert json.loads(sub_section.body) == [{"user_agent": "moz"}]
    assert sub_section.heuristic is None
    # log.warning(sub_section.tags)
    assert sub_section.tags == {"network.user_agent": ["moz"]}


def test_with_unexpected_data(
    hatching_result_instance: hatching_result_instance,
):
    """Validate the http ResultSection is created properly when weird data is presented.

    Expects a section with a single sub-section for user-agent and associated tags.
    """

    # http traffic dict - response from _process_http_traffic()
    http_traff = {
        17: {
            "http_request": {
                "method": "POST",
                # "url": "http://1.1.1.1/test",
                "request": "POST / HTTP/1.1",
                "headers": {"user-agent": "moz"},
            },
            "http_response": {"status": "200", "response": "HTTP/1.0 200 OK"},
        }
    }
    filtered_flow_ids = set()
    section = hatching_result_instance._build_network_http_sub_section(
        http_traffic=http_traff, filtered_flow_ids=filtered_flow_ids
    )

    # Validate main section
    assert section is not None
    assert section.title_text == "HTTP Traffic"
    assert section.body_format == BODY_FORMAT.TEXT
    # log.warning(section.body)
    assert section.body is None
    assert section.heuristic is None
    assert section.tags == {}

    #
    # Validate each sub-section
    #
    assert len(section.subsections) == 1

    #
    # Extracted User Agents from Headers
    sub_section = find_result_section(
        section.subsections, "Extracted User Agents from Headers"
    )
    assert sub_section is not None
    assert sub_section.title_text == "Extracted User Agents from Headers"
    assert sub_section.body_format == BODY_FORMAT.TABLE
    # log.warning(sub_section.body)
    assert json.loads(sub_section.body) == [{"user_agent": "moz"}]
    assert sub_section.heuristic is None
    # log.warning(sub_section.tags)
    assert sub_section.tags == {"network.user_agent": ["moz"]}


def test_domain_fronting_sub_section(
    hatching_result_instance: hatching_result_instance,
):
    """Validate the http ResultSection is created properly when domain-fronting is detected."""

    # http traffic dict - response from _process_http_traffic()
    http_traff = {
        17: {
            "http_request": {
                "method": "POST",
                "url": "http://test.local/test",
                "request": "POST / HTTP/1.1",
                "headers": {"host": "1.1.1.1"},
            },
            "http_response": {"status": "200", "response": "HTTP/1.0 200 OK"},
        }
    }
    filtered_flow_ids = set()
    section = hatching_result_instance._build_network_http_sub_section(
        http_traffic=http_traff, filtered_flow_ids=filtered_flow_ids
    )

    # Validate main section
    assert section is not None
    assert section.title_text == "HTTP Traffic"
    assert section.body_format == BODY_FORMAT.TEXT
    # log.warning(section.body)
    assert section.body is None
    assert section.heuristic is None
    assert section.tags == {}

    #
    # Validate each sub-section
    #
    assert len(section.subsections) == 2

    #
    # Extracted URIs sub-section
    sub_section = find_result_section(section.subsections, "Extracted URIs")
    assert sub_section is not None
    assert sub_section.title_text == "Extracted URIs"
    assert sub_section.body_format == BODY_FORMAT.TABLE
    # log.warning(sub_section.body)
    assert json.loads(sub_section.body) == [{"uri": "http://test.local/test"}]
    assert sub_section.heuristic is None
    # log.warning(sub_section.tags)
    assert sub_section.tags == {
        "network.dynamic.domain": ["test.local"],
        "network.dynamic.uri": ["http://test.local/test"],
        "network.dynamic.uri_path": ["/test"],
    }

    #
    # Domain Fronting
    sub_section = find_result_section(section.subsections, "Domain Fronting")
    assert sub_section is not None
    assert sub_section.title_text == "Domain Fronting"
    assert sub_section.body_format == BODY_FORMAT.TABLE
    # log.warning(sub_section.body)
    assert json.loads(sub_section.body) == [
        {"uri_domain": "test.local", "host_header_domain": "1.1.1.1"}
    ]
    assert sub_section.heuristic.heur_id == 200
    assert sub_section.heuristic.attack_ids == []
    assert sub_section.heuristic.signatures == {}
    assert sub_section.heuristic.score == 500
    # log.warning(sub_section.tags)
    assert sub_section.tags == {
        "network.dynamic.domain": ["test.local"],
        "network.dynamic.ip": ["1.1.1.1"],
    }


def test_tag_in_safelist_not_generated(
    hatching_result_instance: hatching_result_instance,
):
    """Validate the appropriate tags are there given items in the safelist."""

    # http traffic dict - response from _process_http_traffic()
    http_traff = {
        17: {
            "http_request": {
                "method": "POST",
                "url": "http://1.1.1.1/test",
                "request": "POST / HTTP/1.1",
                "headers": {"user-agent": "moz", "host": "1.1.1.1"},
            },
            "http_response": {"status": "200", "response": "HTTP/1.0 200 OK"},
        }
    }
    filtered_flow_ids = set()
    hatching_result_instance.safelist = {
        "match": {"network.dynamic.ip": ["1.1.1.1"], "network.user_agent": ["moz"]}
    }
    section = hatching_result_instance._build_network_http_sub_section(
        http_traffic=http_traff, filtered_flow_ids=filtered_flow_ids
    )

    # Validate main section
    assert section is not None
    assert section.tags == {}

    #
    # Validate each sub-section
    #
    assert len(section.subsections) == 2

    #
    # Extracted URIs sub-section
    sub_section = find_result_section(section.subsections, "Extracted URIs")
    # log.warning(sub_section.tags)
    assert sub_section.tags == {
        "network.dynamic.uri": ["http://1.1.1.1/test"],
        "network.dynamic.uri_path": ["/test"],
    }

    #
    # Extracted User Agents from Headers
    sub_section = find_result_section(
        section.subsections, "Extracted User Agents from Headers"
    )
    assert sub_section is not None
    # log.warning(sub_section.tags)
    assert sub_section.tags == {}


def test_returns_none(
    hatching_result_instance: hatching_result_instance,
):
    """Validate the Result is returned as None when no data presented."""

    http_traff = {}
    filtered_flow_ids = set()
    section = hatching_result_instance._build_network_http_sub_section(
        http_traffic=http_traff, filtered_flow_ids=filtered_flow_ids
    )
    assert section is None

    http_traff = None
    filtered_flow_ids = None
    section = hatching_result_instance._build_network_http_sub_section(
        http_traffic=http_traff, filtered_flow_ids=filtered_flow_ids
    )
    assert section is None

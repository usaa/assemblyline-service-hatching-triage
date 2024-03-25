import pytest
import json
import logging as log

from assemblyline_v4_service.common.result import BODY_FORMAT
from .utils import hatching_result_instance


def test_process_http_traffic(
    hatching_result_instance: hatching_result_instance,
):
    """Validate the basic happy path of processing the hatching network traffic into the expected http traffic
    structure.
    Including the properly created http-headers.
    """

    # Abbreviated example data created from a dynamic analysis triage report: network key
    hatching_network = {
        "requests": [
            {
                "flow": 9,
                "dns_request": {
                    "domains": ["115.140.84.100.in-addr.arpa"],
                },
            },
            {
                "flow": 9,
                "dns_response": {
                    "domains": ["115.140.84.100.in-addr.arpa"],
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
    }

    http_traff, filtered_flow_ids = hatching_result_instance._process_http_traffic(
        hatching_network=hatching_network
    )
    # log.warning(http_traff)
    # log.warning(filtered_flow_ids)
    assert http_traff == {
        17: {
            "http_request": {
                "method": "POST",
                "url": "http://1.1.1.1/",
                "request": "POST / HTTP/1.1",
                "headers": {"user-agent": "moz", "host": "1.1.1.1"},
            },
            "http_response": {"status": "200", "response": "HTTP/1.0 200 OK"},
        }
    }
    assert len(filtered_flow_ids) == 0


def test_process_http_traffic_with_ports(
    hatching_result_instance: hatching_result_instance,
):
    """Validate that when http ports is present, that the traffic is parsed properly."""

    # Abbreviated example data created from a dynamic analysis triage report: network key
    hatching_network = {
        "requests": [
            {
                "flow": 44,
                "index": 1,
                "http_request": {
                    "method": "GET",
                    "url": "https://1.1.1.1:8080/jDj3DDzj",
                    "request": "GET /jDj3DDzj HTTP/1.1",
                    "headers": [
                        "Host: 1.1.1.1:8080",
                        "Connection: Keep-Alive",
                        "Cache-Control: no-cache",
                    ],
                },
            },
            {
                "flow": 44,
                "index": 1,
                "http_response": {"status": "200", "response": "HTTP/1.0 200 OK"},
            },
        ],
    }

    http_traff, filtered_flow_ids = hatching_result_instance._process_http_traffic(
        hatching_network=hatching_network
    )
    # log.warning(http_traff)
    # log.warning(filtered_flow_ids)
    assert http_traff == {
        44: {
            "http_request": {
                "method": "GET",
                "url": "https://1.1.1.1:8080/jDj3DDzj",
                "request": "GET /jDj3DDzj HTTP/1.1",
                "headers": {"host": "1.1.1.1:8080"},
            },
            "http_response": {"status": "200", "response": "HTTP/1.0 200 OK"},
        }
    }
    assert len(filtered_flow_ids) == 0


def test_process_http_traffic_when_flow_is_in_filtered_list(
    hatching_result_instance: hatching_result_instance,
):
    """
    Validate the returned http-traffic is filtered from any safe-listed flows based on the safelisted hosts/uris.
    """

    # Abbreviated example data created from a dynamic analysis triage report: network key
    hatching_network = {
        "requests": [
            {
                "flow": 20,
                "index": 1,
                "http_request": {
                    "method": "POST",
                    "url": "http://1.1.1.2/",
                    "request": "POST / HTTP/1.1",
                    "headers": [
                        "Accept: */*",
                        "Content-Type: application/x-www-form-urlencoded; charset=utf-8",
                        "User-Agent: moz",
                        "Host: 1.1.1.2",
                    ],
                },
            },
            {
                "flow": 20,
                "index": 1,
                "http_response": {"status": "200", "response": "HTTP/1.0 200 OK"},
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
    }

    hatching_result_instance.safelist = {"match": {"network.dynamic.ip": ["1.1.1.2"]}}
    http_traff, filtered_flow_ids = hatching_result_instance._process_http_traffic(
        hatching_network=hatching_network
    )
    # log.warning(http_traff)
    # log.warning(filtered_flow_ids)
    assert http_traff == {
        17: {
            "http_request": {
                "method": "POST",
                "url": "http://1.1.1.1/",
                "request": "POST / HTTP/1.1",
                "headers": {"user-agent": "moz", "host": "1.1.1.1"},
            },
            "http_response": {"status": "200", "response": "HTTP/1.0 200 OK"},
        }
    }
    assert len(filtered_flow_ids) == 1
    assert 20 in filtered_flow_ids


def test_no_http_traffic(
    hatching_result_instance: hatching_result_instance,
):
    """Validate empty dict returned when there are no http-requests in the input."""

    # Abbreviated example data created from a dynamic analysis triage report: network key
    hatching_network = {"requests": []}

    http_traff, filtered_flow_ids = hatching_result_instance._process_http_traffic(
        hatching_network=hatching_network
    )
    # log.warning(http_traff)
    # log.warning(filtered_flow_ids)
    assert http_traff == {}
    assert len(filtered_flow_ids) == 0

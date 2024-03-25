import pytest
import json
import logging as log

from hatching.hatching_result import detect_domain_fronting


def test_detect_domain_fronting():
    """Validate when it's detected and when it's not"""

    # http traffic dict - response from _process_http_traffic()
    http_traff = {
        17: {
            "http_request": {
                "method": "POST",
                "url": "http://test.local/test",
                "request": "POST / HTTP/1.1",
                "headers": {"user-agent": "moz", "host": "1.1.1.1"},
            },
            "http_response": {"status": "200", "response": "HTTP/1.0 200 OK"},
        }
    }

    is_dom_fronting = detect_domain_fronting(http_traff)
    assert is_dom_fronting == [{"host": "1.1.1.1", "uri_domain": "test.local"}]
    http_traff = {
        17: {
            "http_request": {
                "method": "POST",
                "url": "http://test.local/test",
                "request": "POST / HTTP/1.1",
                "headers": {"user-agent": "moz", "host": "test.local"},
            },
            "http_response": {"status": "200", "response": "HTTP/1.0 200 OK"},
        }
    }
    is_dom_fronting = detect_domain_fronting(http_traff)
    assert is_dom_fronting is None

    # validate when a port is listed and matches
    http_traff = {
        20: {
            "http_request": {
                "method": "GET",
                "url": "https://127.0.0.1:8080/ugujATlSfwX",
                "request": "GET /ugujATlSfwX HTTP/1.1",
                "headers": {"host": "127.0.0.1:8080"},
            },
            "http_response": {"status": "200", "response": "HTTP/1.0 200 OK"},
        }
    }
    is_dom_fronting = detect_domain_fronting(http_traff)
    assert is_dom_fronting is None

    # validate when the port isn't present in the host header but in the url
    http_traff = {
        20: {
            "http_request": {
                "method": "GET",
                "url": "https://127.0.0.1:8080/ugujATlSfwX",
                "request": "GET /ugujATlSfwX HTTP/1.1",
                "headers": {"host": "127.0.0.1"},
            },
            "http_response": {"status": "200", "response": "HTTP/1.0 200 OK"},
        }
    }
    is_dom_fronting = detect_domain_fronting(http_traff)
    assert is_dom_fronting == [{"host": "127.0.0.1", "uri_domain": "127.0.0.1:8080"}]


def test_invalid_data():
    """Validate when it's detected and when it's not"""

    http_traff = {}
    is_dom_fronting = detect_domain_fronting(http_traff)
    assert is_dom_fronting is None

    http_traff = None
    is_dom_fronting = detect_domain_fronting(http_traff)
    assert is_dom_fronting is None

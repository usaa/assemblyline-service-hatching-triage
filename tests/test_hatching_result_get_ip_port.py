import pytest
import json
import logging as log

from hatching.hatching_result import get_ip_port


def test_get_ip_port():
    """Validate various valid scenarios for returning the IP/Port separately"""

    inp = "127.0.0.1:100"
    ip, port = get_ip_port(inp)
    assert ip == "127.0.0.1"
    assert port == "100"

    inp = "127.0.0.1"
    ip, port = get_ip_port(inp)
    assert ip == "127.0.0.1"
    assert port is None

    inp = "127.0.0.1:100"
    ip, port = get_ip_port(inp)
    assert ip == "127.0.0.1"
    assert port == "100"


def test_invlalid_input():
    """Validate various invalid input scenarios return nothing and log the error."""

    inp = ""
    ip, port = get_ip_port(inp)
    assert ip is None
    assert port is None

    inp = None
    ip, port = get_ip_port(inp)
    assert ip is None
    assert port is None

    inp = "testme"
    ip, port = get_ip_port(inp)
    assert ip is None
    assert port is None

    inp = "test:me"
    ip, port = get_ip_port(inp)
    assert ip is None
    assert port is None

    inp = "2001:0000:130F:0000:0000:09C0:876A:130B:25"
    ip, port = get_ip_port(inp)
    assert ip is None
    assert port is None

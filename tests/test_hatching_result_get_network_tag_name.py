import pytest
import json
import logging as log

from hatching.hatching_result import get_network_tag_name


def test_get_network_tag_name():
    """Validate various valid scenarios for static and dynamic domains/ips"""

    inp = "test.local"
    is_static_analysis = True
    tag_name = get_network_tag_name(inp, is_static_analysis=is_static_analysis)
    assert tag_name == "network.static.domain"

    inp = "test.local"
    is_static_analysis = False
    tag_name = get_network_tag_name(inp, is_static_analysis=is_static_analysis)
    assert tag_name == "network.dynamic.domain"

    inp = "1.1.1.1"
    is_static_analysis = True
    tag_name = get_network_tag_name(inp, is_static_analysis=is_static_analysis)
    assert tag_name == "network.static.ip"

    inp = "1.1.1.1"
    is_static_analysis = False
    tag_name = get_network_tag_name(inp, is_static_analysis=is_static_analysis)
    assert tag_name == "network.dynamic.ip"


def test_invlalid_input():
    """Validate various invalid input scenarios return nothing and log the error."""

    inp = ""
    is_static_analysis = False
    tag_name = get_network_tag_name(inp, is_static_analysis=is_static_analysis)
    assert tag_name is None

    inp = None
    is_static_analysis = False
    tag_name = get_network_tag_name(inp, is_static_analysis=is_static_analysis)
    assert tag_name is None

    inp = "notvalid"
    is_static_analysis = False
    tag_name = get_network_tag_name(inp, is_static_analysis=is_static_analysis)
    assert tag_name is None

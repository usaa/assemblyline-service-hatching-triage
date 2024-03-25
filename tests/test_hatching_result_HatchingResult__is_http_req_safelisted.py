import pytest
import json
import logging as log

from assemblyline_v4_service.common.result import BODY_FORMAT
from .utils import hatching_result_instance


def test_is_http_req_safelisted(
    hatching_result_instance: hatching_result_instance,
):
    """Validate various scenarios for determining whether the host or uri is in the system safelist."""

    host = "test.local"
    uri = "http://test.local/path1"

    # Scenario 1 - domain in safelist
    hatching_result_instance.safelist = {
        "match": {"network.dynamic.domain": ["test.local"]}
    }
    is_safelisted = hatching_result_instance._is_http_req_safelisted(host, uri)
    assert is_safelisted is True

    # Scenario 2 - uri in safelist
    hatching_result_instance.safelist = {
        "match": {"network.dynamic.uri": ["http://test.local/path1"]}
    }
    is_safelisted = hatching_result_instance._is_http_req_safelisted(host, uri)
    assert is_safelisted is True

    # Scenario 3 - neither in safelist
    hatching_result_instance.safelist = {}
    is_safelisted = hatching_result_instance._is_http_req_safelisted(host, uri)
    assert is_safelisted is False

    # Scenario 4 - ip in safelist
    host = "1.1.1.1"
    uri = "http://1.1.1.1/path1"
    hatching_result_instance.safelist = {"match": {"network.dynamic.ip": ["1.1.1.1"]}}
    is_safelisted = hatching_result_instance._is_http_req_safelisted(host, uri)
    assert is_safelisted is True


def test_invalid_input(
    hatching_result_instance: hatching_result_instance,
):
    """Validate response when invalid input sent in."""

    host = None
    uri = None

    hatching_result_instance.safelist = {}
    is_safelisted = hatching_result_instance._is_http_req_safelisted(host, uri)
    assert is_safelisted is False

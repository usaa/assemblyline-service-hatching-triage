import pytest
import json
import logging as log

from assemblyline_v4_service.common.result import BODY_FORMAT
from .utils import hatching_result_instance


def test_is_dns_req_safelisted(
    hatching_result_instance: hatching_result_instance,
):
    """Validate various scenarios for determining whether the host in a dns request is in the system safelist."""

    host = "test.local"

    # Scenario 1 - domain in safelist
    hatching_result_instance.safelist = {
        "match": {"network.dynamic.domain": ["test.local"]}
    }
    is_safelisted = hatching_result_instance._is_dns_req_safelisted(host)
    assert is_safelisted is True

    # Scenario 3 - not in safelist
    hatching_result_instance.safelist = {}
    is_safelisted = hatching_result_instance._is_dns_req_safelisted(host)
    assert is_safelisted is False

    # Scenario 4 - ip in safelist
    host = "1.1.1.1"
    hatching_result_instance.safelist = {"match": {"network.dynamic.ip": ["1.1.1.1"]}}
    is_safelisted = hatching_result_instance._is_dns_req_safelisted(host)
    assert is_safelisted is True


def test_invalid_input(
    hatching_result_instance: hatching_result_instance,
):
    """Validate response when invalid input sent in."""

    host = ""
    hatching_result_instance.safelist = {}
    is_safelisted = hatching_result_instance._is_dns_req_safelisted(host)
    assert is_safelisted is False

    host = None
    hatching_result_instance.safelist = {}
    is_safelisted = hatching_result_instance._is_dns_req_safelisted(host)
    assert is_safelisted is False

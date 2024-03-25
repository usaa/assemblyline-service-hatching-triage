import pytest
import json
import logging as log

from assemblyline_v4_service.common.result import BODY_FORMAT
from .utils import hatching_result_instance


def test_process_dns(
    hatching_result_instance: hatching_result_instance,
):
    """Validate the basic happy path of processing the hatching network traffic into the expected dns map structure."""

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
                "flow": 35,
                "dns_request": {
                    "domains": ["115.140.84.100.in-addr.arpa"],
                },
            },
            {
                "flow": 35,
                "dns_response": {
                    "domains": ["115.140.84.100.in-addr.arpa"],
                    "ip": ["2.2.2.2"],
                },
            },
            {
                "flow": 36,
                "dns_request": {
                    "domains": ["3.3.3.3.in-addr.arpa"],
                },
            },
            {
                "flow": 36,
                "dns_response": {
                    "domains": ["3.3.3.3.in-addr.arpa"],
                    "ip": ["3.3.3.3"],
                },
            },
        ],
    }

    dns_map, filtered_flow_ids = hatching_result_instance._process_dns(
        hatching_network=hatching_network
    )
    # log.warning(dns_map)
    # log.warning(filtered_flow_ids)
    assert dns_map == {
        "domain_map": {
            "test.local": ["1.1.1.1", "1.1.1.2"],
            "3.3.3.3.in-addr.arpa": ["3.3.3.3"],
        },
        "observed_ips": ["1.1.1.1", "1.1.1.2", "3.3.3.3"],
        "observed_domains": ["test.local", "3.3.3.3.in-addr.arpa"],
    }
    assert 35 in filtered_flow_ids
    assert len(filtered_flow_ids) == 1


def test_process_dns_when_flow_is_in_filtered_list(
    hatching_result_instance: hatching_result_instance,
):
    """
    Validate the returned http-traffic is filtered from any safe-listed flows based on the safelisted hosts/uris.
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
                "flow": 35,
                "dns_request": {
                    "domains": ["115.140.84.100.in-addr.arpa"],
                },
            },
            {
                "flow": 35,
                "dns_response": {
                    "domains": ["115.140.84.100.in-addr.arpa"],
                    "ip": ["2.2.2.2"],
                },
            },
        ],
    }

    hatching_result_instance.safelist = {
        "match": {"network.dynamic.domain": ["test.local"]}
    }
    dns_map, filtered_flow_ids = hatching_result_instance._process_dns(
        hatching_network=hatching_network
    )
    # log.warning(dns_map)
    # log.warning(filtered_flow_ids)
    assert dns_map == {
        "domain_map": {},
        "observed_ips": [],
        "observed_domains": [],
    }
    assert 26 in filtered_flow_ids
    assert 35 in filtered_flow_ids
    assert len(filtered_flow_ids) == 2


def test_no_dns_traffic(
    hatching_result_instance: hatching_result_instance,
):
    """Validate dns basic structure map (empty) when there are no dns-requests in the input."""

    # Abbreviated example data created from a dynamic analysis triage report: network key
    hatching_network = {"requests": []}

    dns_map, filtered_flow_ids = hatching_result_instance._process_dns(
        hatching_network=hatching_network
    )
    # log.warning(dns_map)
    # log.warning(filtered_flow_ids)
    assert dns_map == {
        "domain_map": {},
        "observed_ips": [],
        "observed_domains": [],
    }
    assert len(filtered_flow_ids) == 0

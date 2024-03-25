import pytest
import json
import logging as log

from assemblyline_v4_service.common.result import BODY_FORMAT
from .utils import hatching_result_instance


def test_process_network_flow_traffic(
    hatching_result_instance: hatching_result_instance,
):
    """Validate the filter-flow-ids are filtered from the network-flows traffic."""

    # Abbreviated example data created from a dynamic analysis triage report: .network key
    hatching_network = {
        "flows": [
            {
                "id": 3,
                "src": "10.127.0.30:64935",
                "dst": "1.1.1.1:80",
                "protocols": ["http"],
                "domain": "1.1.1.1",
            },
            {
                "id": 5,
                "src": "10.127.0.30:52407",
                "dst": "8.8.8.8:53",
                "protocols": ["dns"],
                "domain": "8.8.8.8.in-addr.arpa",
            },
            {
                "id": 9,
                "src": "10.127.0.30:55226",
                "dst": "2.2.2.2:443",
                "protocols": ["tls"],
                "domain": "test.local",
                "tls_ja3": "8b26c12685bcb922eabb5cea45c16a14",
                "tls_ja3s": "f4febc55ea12b31ae17cfb7e614afda8",
                "tls_sni": "test.local",
            },
        ]
    }
    filtered_flow_ids = [3, 9]
    filtered_flows = hatching_result_instance._process_network_flow_traffic(
        hatching_network=hatching_network, filtered_flow_ids=filtered_flow_ids
    )
    # log.warning(filtered_flows)
    assert filtered_flows == [
        {
            "id": 5,
            "src": "10.127.0.30:52407",
            "dst": "8.8.8.8:53",
            "protocols": ["dns"],
            "domain": "8.8.8.8.in-addr.arpa",
        },
    ]


def test_no_dns_traffic(
    hatching_result_instance: hatching_result_instance,
):
    """Validate an empty list is returned when there is no network flows specified in the input."""

    # scenario 1 - empty lists
    hatching_network = {"flows": []}
    filtered_flow_ids = []
    filtered_flows = hatching_result_instance._process_network_flow_traffic(
        hatching_network=hatching_network, filtered_flow_ids=filtered_flow_ids
    )
    assert filtered_flows == []

    # scenario 2 - Null inputs
    hatching_network = None
    filtered_flow_ids = None
    filtered_flows = hatching_result_instance._process_network_flow_traffic(
        hatching_network=hatching_network, filtered_flow_ids=filtered_flow_ids
    )
    assert filtered_flows == []

    # scenario 3 - Null filtered_flow_ids
    hatching_network = {
        "flows": [
            {
                "id": 5,
                "src": "10.127.0.30:52407",
                "dst": "8.8.8.8:53",
                "protocols": ["dns"],
                "domain": "8.8.8.8.in-addr.arpa",
            },
        ],
    }
    filtered_flow_ids = None
    filtered_flows = hatching_result_instance._process_network_flow_traffic(
        hatching_network=hatching_network, filtered_flow_ids=filtered_flow_ids
    )
    assert filtered_flows == [
        {
            "id": 5,
            "src": "10.127.0.30:52407",
            "dst": "8.8.8.8:53",
            "protocols": ["dns"],
            "domain": "8.8.8.8.in-addr.arpa",
        },
    ]

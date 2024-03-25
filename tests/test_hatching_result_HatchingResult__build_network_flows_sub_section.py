import pytest
import json
import logging as log

from assemblyline_v4_service.common.result import BODY_FORMAT
from .utils import hatching_result_instance, find_result_section


def test_build_network_flows_sub_section(
    hatching_result_instance: hatching_result_instance,
):
    """Validate the network flows section is created properly for happy path input with network-flows data.

    Expects a ResultTableSection with associated tags.
    """

    # abbreviated view of network flows traffic - .network.flows key from a dynamic triage report
    flows = [
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
    section = hatching_result_instance._build_network_flows_sub_section(
        network_flows=flows
    )

    # Validate main section
    assert section is not None
    assert section.title_text == "Network Flows"
    assert section.body_format == BODY_FORMAT.TABLE
    # log.warning(section.body)
    assert json.loads(section.body) == [
        {
            "domain": "test.local",
            "ja3": "8b26c12685bcb922eabb5cea45c16a14",
            "ja3s": "f4febc55ea12b31ae17cfb7e614afda8",
        }
    ]
    assert section.heuristic is None
    # log.warning(section.tags)
    assert section.tags == {
        "network.protocol": ["http", "dns", "tls"],
        "network.port": ["80", "53", "443"],
        "network.tls.sni": ["test.local"],
        "network.tls.ja3_hash": ["8b26c12685bcb922eabb5cea45c16a14"],
    }
    assert len(section.subsections) == 0


def test_with_different_data(
    hatching_result_instance: hatching_result_instance,
):
    """Validate the network flows section is created properly for a different set of network-flows data.

    Expects a ResultTableSection to have no body but has tags.
    """
    # abbreviated view of network flows traffic - .network.flows key from a dynamic triage report
    flows = [
        {
            "id": 3,
            "src": "10.127.0.30:64935",
            "dst": "1.1.1.1:80",
            "protocols": ["http", "rando"],
            "domain": "1.1.1.1",
        },
        {
            "id": 15,
            "src": "10.127.0.30:60222",
            "dst": "224.0.0.251:5353",
        },
    ]
    section = hatching_result_instance._build_network_flows_sub_section(
        network_flows=flows
    )

    # Validate main section
    assert section is not None
    assert section.title_text == "Network Flows"
    assert section.body_format == BODY_FORMAT.TABLE
    # log.warning(section.body)
    assert section.body is None
    assert section.heuristic is None
    # log.warning(section.tags)
    assert section.tags == {
        "network.protocol": ["http", "rando"],
        "network.port": ["80", "5353"],
    }
    assert len(section.subsections) == 0


def test_tag_in_safelist_not_generated(
    hatching_result_instance: hatching_result_instance,
):
    """Validate the appropriate tags are there given items in the safelist."""

    flows = [
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
    hatching_result_instance.safelist = {
        "match": {
            "network.protocol": ["tls"],
            "network.port": ["443"],
            "network.tls.ja3_hash": ["8b26c12685bcb922eabb5cea45c16a14"],
            "network.tls.sni": ["test.local"],
        }
    }
    section = hatching_result_instance._build_network_flows_sub_section(
        network_flows=flows
    )

    # Validate main section
    assert section is not None
    assert section.title_text == "Network Flows"
    assert section.body_format == BODY_FORMAT.TABLE
    # log.warning(section.body)
    assert json.loads(section.body) == [
        {
            "domain": "test.local",
            "ja3": "8b26c12685bcb922eabb5cea45c16a14",
            "ja3s": "f4febc55ea12b31ae17cfb7e614afda8",
        }
    ]
    assert section.heuristic is None
    # log.warning(section.tags)
    assert section.tags == {
        "network.protocol": ["http", "dns"],
        "network.port": ["80", "53"],
    }
    assert len(section.subsections) == 0


def test_returns_none(
    hatching_result_instance: hatching_result_instance,
):
    """Validate the Result is returned as None when no data presented."""

    flows = []
    section = hatching_result_instance._build_network_flows_sub_section(
        network_flows=flows
    )
    assert section is None

    flows = None
    section = hatching_result_instance._build_network_flows_sub_section(
        network_flows=flows
    )
    assert section is None

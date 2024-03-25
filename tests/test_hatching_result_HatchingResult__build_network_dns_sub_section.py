import pytest
import json
import logging as log

from assemblyline_v4_service.common.result import BODY_FORMAT
from .utils import hatching_result_instance, find_result_section


def test_build_network_dns_sub_section(
    hatching_result_instance: hatching_result_instance,
):
    """Validate the dns section is created properly for happy path input with dns data.

    Expects a ResultTableSection with associated tags.
    """

    # dns traffic map - response from _process_dns_traffic()
    dns_map = {
        "domain_map": {"test.local": ["1.1.1.2", "1.1.1.1", "100.65.1.1"]},
        "observed_ips": ["1.1.1.2", "1.1.1.1", "100.65.1.1"],
        "observed_domains": ["test.local"],
    }
    section = hatching_result_instance._build_network_dns_sub_section(dns_map=dns_map)

    # Validate main section
    assert section is not None
    assert section.title_text == "DNS Resolutions"
    assert section.body_format == BODY_FORMAT.TABLE
    # log.warning(section.body)
    assert json.loads(section.body) == [
        {
            "domain": "test.local",
            "ips": "1.1.1.2, 1.1.1.1, 100.65.1.1 (Hatching Simulated Network)",
        }
    ]
    assert section.heuristic is None
    # log.warning(section.tags)
    assert section.tags == {
        "network.dynamic.domain": ["test.local"],
        "network.dynamic.ip": ["1.1.1.2", "1.1.1.1", "100.65.1.1"],
    }
    assert len(section.subsections) == 0


def test_with_different_data(
    hatching_result_instance: hatching_result_instance,
):
    """Validate the dns section is created properly when observied_ips and observed_domains contains other indicators.

    Expects a ResultTableSection with the dns-ip map and separately have tags only to represent the "observed"
    ips/domains.
    """

    # dns traffic map - response from _process_dns_traffic()
    dns_map = {
        "domain_map": {"test.local": ["1.1.1.1"]},
        "observed_ips": ["2.2.2.2", "3.3.3.3"],
        "observed_domains": ["test.local", "test2.local"],
    }
    section = hatching_result_instance._build_network_dns_sub_section(dns_map=dns_map)

    # Validate main section
    assert section is not None
    assert section.title_text == "DNS Resolutions"
    assert section.body_format == BODY_FORMAT.TABLE
    # log.warning(section.body)
    assert json.loads(section.body) == [{"domain": "test.local", "ips": "1.1.1.1"}]
    assert section.heuristic is None
    # log.warning(section.tags)
    assert section.tags == {
        "network.dynamic.domain": ["test.local", "test2.local"],
        "network.dynamic.ip": ["2.2.2.2", "3.3.3.3", "1.1.1.1"],
    }
    assert len(section.subsections) == 0


def test_tag_in_safelist_not_generated(
    hatching_result_instance: hatching_result_instance,
):
    """Validate the appropriate tags are there given items in the safelist."""

    # dns traffic map - response from _process_dns_traffic()
    dns_map = {
        "domain_map": {"test.local": ["1.1.1.2", "1.1.1.1"]},
        "observed_ips": ["1.1.1.2", "1.1.1.1"],
        "observed_domains": ["test.local"],
    }
    hatching_result_instance.safelist = {
        "match": {
            "network.dynamic.ip": ["1.1.1.1"],
            "network.dynamic.domain": ["test.local"],
        }
    }
    section = hatching_result_instance._build_network_dns_sub_section(dns_map=dns_map)

    # Validate main section
    assert section is not None
    assert section.title_text == "DNS Resolutions"
    assert section.body_format == BODY_FORMAT.TABLE
    # log.warning(section.body)
    # Note: even though 'test.local' and '1.1.1.1' are in the safelist, they'll still show up in the table results.
    #  However, the tags are filtered and not created.
    #  In a real scenario, the data would have been filtered with the process_dns() which is the input to
    #  _build_network_dns_sub_section() and therefore would not have even been sent into this method.
    assert json.loads(section.body) == [
        {"domain": "test.local", "ips": "1.1.1.2, 1.1.1.1"}
    ]
    assert section.heuristic is None
    # log.warning(section.tags)
    assert section.tags == {"network.dynamic.ip": ["1.1.1.2"]}
    assert len(section.subsections) == 0


def test_returns_none(
    hatching_result_instance: hatching_result_instance,
):
    """Validate the Result is returned as None when no data presented."""

    dns_map = {}
    section = hatching_result_instance._build_network_dns_sub_section(dns_map=dns_map)
    assert section is None

    dns_map = None
    section = hatching_result_instance._build_network_dns_sub_section(dns_map=dns_map)
    assert section is None

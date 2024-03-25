import pytest
import json
import logging as log

from hatching.hatching_result import is_domain_a_private_rev_dns_lookup


def test_is_domain_a_private_rev_dns_lookup():
    """Validate whether the domain is a reverse lookup using the private ip space hatching uses."""

    dom = "177.204.111.100.in-addr.arpa"
    assert is_domain_a_private_rev_dns_lookup(dom) is True

    dom = "1.2.64.100.in-addr.arpa"
    assert is_domain_a_private_rev_dns_lookup(dom) is True

    dom = "8.8.8.8.in-addr.arpa"
    assert is_domain_a_private_rev_dns_lookup(dom) is False

    dom = "test.local"
    assert is_domain_a_private_rev_dns_lookup(dom) is False


def test_invlalid_input(caplog):
    """Validate various invalid input scenarios return None and logs the error."""

    dom = None
    assert is_domain_a_private_rev_dns_lookup(dom) is False

    dom = ""
    assert is_domain_a_private_rev_dns_lookup(dom) is False

    dom = "junk.junk.in-addr.arpa"
    assert is_domain_a_private_rev_dns_lookup(dom) is False

    dom = "1.in-addr.arpa"
    assert is_domain_a_private_rev_dns_lookup(dom) is False

    dom = ".in-addr.arpa"
    assert is_domain_a_private_rev_dns_lookup(dom) is False

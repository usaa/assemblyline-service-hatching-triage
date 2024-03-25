import pytest
import json
import logging as log

from hatching.hatching_result import sanitize_dict


def test_sanitize_dict():
    """Test various scenarios to sanitize a dict."""

    d = {
        "encoded": b"\xff\xfet\x00e\x00s\x00t\x00",
        "nested_dict": {
            "nested_key_1": "nested_key_1val",
            "utf": "résumé",
        },
        "str": "teststr",
        "empty": None,
    }
    # log.warning(sanitize_dict(d))
    assert sanitize_dict(d) == {
        "encoded": "\\xff\\xfet\\x00e\\x00s\\x00t\\x00",
        "nested_dict": {
            "nested_key_1": "nested_key_1val",
            "utf": "r\u00e9sum\u00e9",
        },
        "str": "teststr",
        "empty": None,
    }


def test_invalid_inputs():
    """Test invalid input scenarios."""

    assert sanitize_dict(None) is None

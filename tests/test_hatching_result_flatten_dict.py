import pytest
import json
import logging as log

from hatching.hatching_result import flatten_dict


def test_flatten_dict():
    """Test various scenarios to flatten a dict
    Note: This is just meant to cover the possible results coming back from the Hatching API
    """

    d = {
        "int": 1,
        "str": "val1",
        "nested_dict": {
            "nested_key_1": "nested_key_1val",
            "nested_key_2": "nested_key_2val",
        },
        "list_of_dicts": [{"key1": "key1val"}, {"key2": "key2val"}],
        "list_of_strs": ["valA", "valB"],
        "list_of_ints": [1, 2, 3],
    }

    assert flatten_dict(d) == {
        "int": 1,
        "str": "val1",
        "nested_dict.nested_key_1": "nested_key_1val",
        "nested_dict.nested_key_2": "nested_key_2val",
        "list_of_dicts.1.key1": "key1val",
        "list_of_dicts.2.key2": "key2val",
        "list_of_strs": ["valA", "valB"],
        "list_of_ints": [1, 2, 3],
    }

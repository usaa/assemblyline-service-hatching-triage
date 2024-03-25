import pytest
import json
import logging as log

from .utils import hatching_service_instance


def test_is_dump_file_to_be_added_to_pipeline(hatching_service_instance):
    """Validate various scenarios for whether a file should be added back to the pipeline for analysis."""

    file_name = "memory/2352-54-0x0000000000400000-0x000000000041F000-memory.dmp"
    dump_origin = "martian"
    analyze_extracted_memory_dumps = True
    is_add = hatching_service_instance._is_dump_file_to_be_added_to_pipeline(
        file_name, dump_origin, analyze_extracted_memory_dumps
    )
    assert is_add is True

    file_name = "2352-54-0x0000000000400000-0x000000000041F000-memory.dmp"
    dump_origin = "martian"
    analyze_extracted_memory_dumps = True
    is_add = hatching_service_instance._is_dump_file_to_be_added_to_pipeline(
        file_name, dump_origin, analyze_extracted_memory_dumps
    )
    assert is_add is True

    file_name = "memory/2352-54-0x0000000000400000-0x000000000041F000-memory.dmp"
    dump_origin = "exception"
    analyze_extracted_memory_dumps = True
    is_add = hatching_service_instance._is_dump_file_to_be_added_to_pipeline(
        file_name, dump_origin, analyze_extracted_memory_dumps
    )
    assert is_add is False

    file_name = "memory/2352-54-0x0000000000400000-0x000000000041F000-memory.dmp"
    dump_origin = "martian"
    analyze_extracted_memory_dumps = False
    is_add = hatching_service_instance._is_dump_file_to_be_added_to_pipeline(
        file_name, dump_origin, analyze_extracted_memory_dumps
    )
    assert is_add is False

    file_name = "files/0x000a0000000142b2-60.dat"
    dump_origin = "martian"
    analyze_extracted_memory_dumps = False
    is_add = hatching_service_instance._is_dump_file_to_be_added_to_pipeline(
        file_name, dump_origin, analyze_extracted_memory_dumps
    )
    assert is_add is True


def test_when_input_is_invalid(hatching_service_instance):
    """Validate various invalid input scenarios."""

    file_name = ""
    dump_origin = "imgload"
    analyze_extracted_memory_dumps = True
    is_add = hatching_service_instance._is_dump_file_to_be_added_to_pipeline(
        file_name, dump_origin, analyze_extracted_memory_dumps
    )
    assert is_add is False

    file_name = None
    dump_origin = "imgload"
    analyze_extracted_memory_dumps = True
    is_add = hatching_service_instance._is_dump_file_to_be_added_to_pipeline(
        file_name, dump_origin, analyze_extracted_memory_dumps
    )
    assert is_add is False

    file_name = "test.txt"
    dump_origin = None
    analyze_extracted_memory_dumps = False
    is_add = hatching_service_instance._is_dump_file_to_be_added_to_pipeline(
        file_name, dump_origin, analyze_extracted_memory_dumps
    )
    assert is_add is True

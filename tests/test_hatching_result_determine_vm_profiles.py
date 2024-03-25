import pytest
import json
import logging as log

from hatching.hatching_result import determine_vm_profiles


def test_determine_vm_profiles():
    """Validate the happy path returns the expected vm profiles"""

    # simplified view of results overview hatching api results
    overview = {
        "tasks": [
            {
                "kind": "behavioral",
                "task_name": "vm-profile-win-1",
            },
            {
                "kind": "behavioral",
                "task_name": "vm-profile-win-2",
            },
            {
                "kind": "static",
            },
        ],
    }

    profiles = determine_vm_profiles(overview)

    assert profiles == ["vm-profile-win-1", "vm-profile-win-2"]


def test_invlalid_input(caplog):
    """Validate various invalid input scenarios return nothing and log the error."""

    # Scenario 1
    overview = {
        "tasks": [
            {
                "kind": "behavioral",
            },
            {
                "kind": "static",
            },
        ],
    }
    profiles = determine_vm_profiles(overview)
    assert profiles == []

    # validate the error is logged
    errors = [
        record for record in caplog.get_records("call") if record.levelno >= log.ERROR
    ]
    # log.warning(errors)
    assert "Unable to determine the VM profile while processing results." in caplog.text
    assert len(errors) == 1

    # Scenario 2
    overview = {}
    profiles = determine_vm_profiles(overview)

    assert profiles == []

    # validate the error is logged
    errors = [
        record for record in caplog.get_records("call") if record.levelno >= log.ERROR
    ]
    # log.warning(errors)
    assert "Unable to determine the VM profile while processing results." in caplog.text

    # Scenario 3
    overview = None
    profiles = determine_vm_profiles(overview)

    assert profiles == []

    # validate the error is logged
    errors = [
        record for record in caplog.get_records("call") if record.levelno >= log.ERROR
    ]
    # log.warning(errors)
    assert "Unable to determine the VM profile while processing results." in caplog.text

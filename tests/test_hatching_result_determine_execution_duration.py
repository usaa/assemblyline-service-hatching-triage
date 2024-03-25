import pytest
import json
import logging as log

from hatching.hatching_result import determine_execution_duration


def test_execution_duration():
    """Validate basic happy path"""

    created_ts = "2023-08-15T12:46:41Z"
    completed_ts = "2023-08-15T12:47:18Z"

    num_secs = determine_execution_duration(created_ts, completed_ts)

    assert num_secs == 37


def test_invlalid_input(caplog):
    """Validate various invalid input scenarios return 0 seconds and log the exception."""

    # invalid input scenario 1
    created_ts = "2023-08-15"
    completed_ts = "2023-08-15T12:47:18Z"

    num_secs = determine_execution_duration(created_ts, completed_ts)

    assert num_secs == 0

    # validate the exception is logged
    errors = [
        record for record in caplog.get_records("call") if record.levelno >= log.ERROR
    ]
    # log.warning(errors)
    assert (
        "Incorrect date formats passed to determine_execution_duration" in caplog.text
    )
    assert len(errors) == 1

    # invalid input scenario 2
    created_ts = "2023-08-15T12:47:18Z"
    completed_ts = "2023-08-15T12:47"

    num_secs = determine_execution_duration(created_ts, completed_ts)

    assert num_secs == 0

    # validate the exception is logged
    errors = [
        record for record in caplog.get_records("call") if record.levelno >= log.ERROR
    ]
    # log.warning(errors)
    assert (
        "Incorrect date formats passed to determine_execution_duration" in caplog.text
    )

    # invalid input scenario 3
    created_ts = None
    completed_ts = None

    num_secs = determine_execution_duration(created_ts, completed_ts)

    assert num_secs == 0

    # validate the exception is logged
    errors = [
        record for record in caplog.get_records("call") if record.levelno >= log.ERROR
    ]
    # log.warning(errors)
    assert (
        "Incorrect date formats passed to determine_execution_duration" in caplog.text
    )

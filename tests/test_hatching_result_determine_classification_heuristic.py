import pytest
import json
import logging as log

from hatching.hatching_result import determine_classification_heuristic


def test_determine_classification_heuristic():
    """Validate basic happy path"""

    hatching_score = 10
    num_secs = determine_classification_heuristic(hatching_score)
    assert num_secs == 2

    hatching_score = 9
    num_secs = determine_classification_heuristic(hatching_score)
    assert num_secs == 3

    hatching_score = 6
    num_secs = determine_classification_heuristic(hatching_score)
    assert num_secs == 4

    hatching_score = 3
    num_secs = determine_classification_heuristic(hatching_score)
    assert num_secs == 5

    hatching_score = 1
    num_secs = determine_classification_heuristic(hatching_score)
    assert num_secs == 6


def test_invlalid_input(caplog):
    """Validate various invalid input scenarios return None and logs the error."""

    # Scenario 1
    hatching_score = None
    heur_id = determine_classification_heuristic(hatching_score)
    assert heur_id is None

    # validate the error is logged
    errors = [
        record for record in caplog.get_records("call") if record.levelno >= log.ERROR
    ]
    assert (
        "Hatching score out of range. Unable to to determine the heuristic."
        in caplog.text
    )
    assert len(errors) == 1

    hatching_score = 11
    heur_id = determine_classification_heuristic(hatching_score)
    assert heur_id is None

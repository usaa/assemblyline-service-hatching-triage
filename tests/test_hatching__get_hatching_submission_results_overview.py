import pytest
import json
import logging as log

from unittest import mock
from unittest.mock import patch
from unittest.mock import MagicMock, PropertyMock

from .utils import hatching_service_instance

from retrying import RetryError
from triage import Client
from triage.client import ServerError
from requests.exceptions import HTTPError


def test_raises_exception_and_error_logged(hatching_service_instance, caplog):
    """Validate a RetryError exception is raised when the max number of attempts occurs.
    Also validate the underlying ServerError exception is logged."""

    # Mock the ServerError
    mock_response = MagicMock()
    mock_response.json.return_value = {"error": {"code": "500", "message": "fail"}}
    exc = ServerError(HTTPError(response=mock_response))

    # Mock the triage_client to raise an exception when called
    hatching_service_instance.triage_client = Client("apikey", "apiurl")
    hatching_service_instance.triage_client.overview_report = MagicMock(side_effect=exc)

    sample_id = "1"
    with pytest.raises(RetryError):
        results = hatching_service_instance._get_hatching_submission_results_overview(
            sample_id
        )

    errors = [
        record for record in caplog.get_records("call") if record.levelno >= log.ERROR
    ]
    assert (
        f"Exception retrieving the overview report for sample_id: {sample_id}"
        in caplog.text
    )
    assert len(errors) == 2

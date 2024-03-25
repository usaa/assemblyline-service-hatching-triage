import pytest
import json
import logging as log

from assemblyline_service_utilities.common.dynamic_service_helper import OntologyResults
from assemblyline_v4_service.common.result import BODY_FORMAT

from .utils import hatching_result_instance


def test_update_ontres_for_dynamic_result_info_section(
    hatching_result_instance: hatching_result_instance,
):
    """Validate the OntologyResults gets a Sandbox instance associated for the basic sandbox metadata.

    Also validate it works when multiple sandbox instances are run for a given submission.
    """

    start_time = "2023-09-19T18:52:26Z"
    end_time = "2023-09-19T18:54:46Z"
    platform = "windows10-2004_x64"
    task_name = "test-profile-1"
    version = "0.3.0"

    hatching_result_instance._update_ontres_for_dynamic_result_info_section(
        task_name=task_name,
        start_time=start_time,
        end_time=end_time,
        platform=platform,
        version=version,
    )

    # log.warning(hatching_result_instance.ontres.sandboxes)
    # log.warning(len(hatching_result_instance.ontres.sandboxes))
    assert len(hatching_result_instance.ontres.sandboxes) == 1

    sb = hatching_result_instance.ontres.sandboxes[0]

    assert sb.sandbox_name == "HATCHING"
    assert sb.sandbox_version == version
    assert sb.analysis_metadata.start_time == start_time
    assert sb.analysis_metadata.end_time == end_time
    assert sb.analysis_metadata.task_id is None
    assert sb.analysis_metadata.routing is None
    assert sb.analysis_metadata.machine_metadata is None

    # Now add a second instance of a sandbox. i.e. a second triage-report
    # scenario is the hatching profile was configured to run multiple VMs for a given submission.
    start_time2 = "2023-09-19T18:52:26Z"
    end_time2 = "2023-09-20T18:54:46Z"
    platform2 = "windows10-2004_x64"
    task_name2 = "test-profile-1"

    hatching_result_instance._update_ontres_for_dynamic_result_info_section(
        task_name=task_name2,
        start_time=start_time2,
        end_time=end_time2,
        platform=platform2,
        version=version,
    )

    assert len(hatching_result_instance.ontres.sandboxes) == 2

    sb = hatching_result_instance.ontres.sandboxes[1]

    assert sb.sandbox_name == "HATCHING"
    assert sb.sandbox_version == version
    assert sb.analysis_metadata.start_time == start_time2
    assert sb.analysis_metadata.end_time == end_time2
    assert sb.analysis_metadata.task_id is None
    assert sb.analysis_metadata.routing is None
    assert sb.analysis_metadata.machine_metadata is None


def test_logs_when_invalid_data(
    hatching_result_instance: hatching_result_instance, caplog
):
    """Validate the Sandbox is not added to the OntologyResult when there is missing data.

    Validate it logs the error.
    """
    start_time = "2023-09-19T18:52:26Z"
    end_time = None
    platform = "windows10-2004_x64"
    task_name = "test-profile-1"
    version = "0.3.0"

    hatching_result_instance._update_ontres_for_dynamic_result_info_section(
        task_name=task_name,
        start_time=start_time,
        end_time=end_time,
        platform=platform,
        version=version,
    )

    # log.warning(hatching_result_instance.ontres.sandboxes)
    # log.warning(len(hatching_result_instance.ontres.sandboxes))
    assert len(hatching_result_instance.ontres.sandboxes) == 0

    # validate the error is logged
    errors = [
        record for record in caplog.get_records("call") if record.levelno >= log.ERROR
    ]
    assert (
        f"Unable to update the OntologyResult. Missing submission metadata for Hatching sample id: {hatching_result_instance.sample_id}"
        in caplog.text
    )
    assert len(errors) == 1

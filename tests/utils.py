import os
import shutil
import pytest
import logging
import json
import pathlib

from typing import Any, Dict, List, Optional, Set, Tuple

from assemblyline_v4_service.common.request import ServiceRequest  # type: ignore
from assemblyline_v4_service.common.result import ResultSection
from assemblyline_v4_service.common.ontology_helper import OntologyHelper
from assemblyline_service_utilities.common.dynamic_service_helper import OntologyResults

from hatching.hatching import Hatching
from hatching.hatching_result import HatchingResult

# Getting absolute paths, names and regexes
CURRENT_FILE_DIR = pathlib.Path(__file__).parent.resolve()
SERVICE_CONFIG_NAME = "service_manifest.yml"
TEMP_SERVICE_CONFIG_PATH = os.path.join(os.getcwd(), SERVICE_CONFIG_NAME)

SERVICE_NAME = "HATCHING"

log = logging.getLogger(__name__)

HATCHING_ENDPOINT_URL = "https://hatching.local"


@pytest.fixture
def hatching_service_instance():
    """
    Create a Hatching instance
    :return: yield Hatching
    """
    yield Hatching()


@pytest.fixture
def hatching_result_with_imported_results(request):
    """
    Create a HatchingResult instance that can setup the hatching_results with local files.

    :param request:
        param 0: Hatching Results dict with location to files to setup as a part of the instance
            {
                "overview_file": "api_samples/230815-aaabbbccc1-overview.json",
                "static_report_file": "api_samples/230815-aaabbbccc1-static.json",
                "triage_report_files": [
                    "api_samples/230815-aaabbbccc1-rpt-triage-behavioral1.json",
                    "api_samples/230815-aaabbbccc1-rpt-triage-behavioral2.json",
                ],
            }
        param 1: hatching sample id

    :return: yield HatchingResult
    """

    hatching_results = {
        "overview": {},
        "static_report": {},
        "triage_reports": [],
    }

    # Read in the reports dict to setup the hatching_results input
    if request.param[0]:
        overview_fp = request.param[0].get("overview_file", None)
        if overview_fp:
            with open(os.path.join(CURRENT_FILE_DIR, overview_fp), "r") as f:
                hatching_results["overview"] = json.load(f)

        static_report_fp = request.param[0].get("static_report_file", None)
        if static_report_fp:
            with open(os.path.join(CURRENT_FILE_DIR, static_report_fp), "r") as f:
                hatching_results["static_report"] = json.load(f)

        for fp in request.param[0].get("triage_report_files", None):
            with open(os.path.join(CURRENT_FILE_DIR, fp), "r") as f:
                hatching_results["triage_reports"].append(json.load(f))

    ontres = OntologyResults(service_name=SERVICE_NAME)

    if request.param[1]:
        sample_id = request.param[1]
    else:
        # set a default if not specified
        sample_id = "230815-xxxyyyzzz1"

    yield HatchingResult(
        hatching_results=hatching_results,
        ontres=ontres,
        web_url=HATCHING_ENDPOINT_URL,
        sample_id=sample_id,
        safelist={},
    )


@pytest.fixture
def hatching_result_instance():
    """
    Create a base HatchingResult instance with the sample_id defaulted to 230815-xxxyyyzzz1

    :return: yield HatchingResult
    """
    hatching_results = {
        "overview": {},
        "static_report": {},
        "triage_reports": [],
    }

    ontres = OntologyResults(service_name=SERVICE_NAME)

    sample_id = "230815-xxxyyyzzz1"

    yield HatchingResult(
        hatching_results=hatching_results,
        ontres=ontres,
        web_url=HATCHING_ENDPOINT_URL,
        sample_id=sample_id,
        safelist={},
    )


def find_result_section(
    result_sections: List[ResultSection], title: str
) -> Optional[ResultSection]:
    """Find a a result section based on the resultsection title

    Args:
        result_sections (List[ResultSection]): List of ResultSections
        title (str): ResultSection title to find

    Returns:
        Optional[ResultSection]: Found ResultSection or None
    """
    for section in result_sections:
        if section.title_text.startswith(title):
            return section

    return None

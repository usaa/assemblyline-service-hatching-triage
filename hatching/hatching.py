"""Hatching AL4 Service."""

import json
import os
import shutil
import uuid

from typing import Any, Dict, List, Optional
from enum import Enum
from retrying import retry  # type: ignore

from assemblyline_v4_service.common.api import ServiceAPIError
from assemblyline_v4_service.common.base import ServiceBase
from assemblyline_v4_service.common.request import ServiceRequest
from assemblyline_v4_service.common.result import (
    ResultSection,
    Result,
    ResultTextSection,
)

from assemblyline_service_utilities.common.dynamic_service_helper import (
    OntologyResults,
    attach_dynamic_ontology,
)
from assemblyline.common import forge
from triage import Client  # type: ignore
from triage.client import ServerError  # type: ignore

from .hatching_result import HatchingResult


Classification = forge.get_classification()

SUBMISSION_POLL_DELAY = 5
REPORT_RETRIEVAL_RETRY_DELAY = 5

SERVICE_NAME = "HATCHING"


class FailedSubmissionException(Exception):
    """Exception class for a failed submission."""


class MissingParamException(Exception):
    """Exception class for missing params."""


class InvalidConfigurationException(Exception):
    """Exception class for an invalid service configuration."""


def _retry_on_none(result) -> bool:
    return result is None


def _retry_on_false(result) -> bool:
    return result is False


class VMPlatform(Enum):
    """VM Platform Enum."""

    WINDOWS = "windows"
    MACOS = "macos"
    LINUX = "linux"
    ANDROID = "android"
    DEFAULT = "default"


class Hatching(ServiceBase):
    """Hatching AL4 service."""

    def __init__(self, config=None):
        """Configure service instance."""
        super(Hatching, self).__init__(config)

        self.service_request = None
        self.triage_client = None
        self.artifact_list: Optional[List[Dict[str, str]]] = None
        self.temp_extracted_files_dir = "/tmp/extracted"
        self.safelist: Dict[str, Dict[str, List[str]]] = {}

    def start(self):
        """Invoke once as the service instance starts."""
        self.log.info("start() from %s service called", self.service_attributes.name)

        host_config = self.config.get("host_config")

        # validate the config params
        self._validate_config()

        self.triage_client = Client(
            host_config.get("api_key"), root_url=host_config.get("api_url")
        )

        try:
            self.safelist = self.get_api_interface().get_safelist()
        except ServiceAPIError:
            self.log.exception(
                "Could not retrieve safelist from service: %s. Continuing without it.",
                self.service_attributes.name,
            )

    def execute(self, request: ServiceRequest):
        """Execute for each file being analyzed.

        Args:
            request (ServiceRequest): AL4 ServiceRequest object
        """
        self.log.info("Processing file: %s", request.sha256)
        self.service_request = request
        self.artifact_list = []
        self._reinit_temp_dir()

        max_file_depth_short_circuit = self.config.get("max_file_depth_short_circuit")

        if (
            max_file_depth_short_circuit is not None
            and request.task.depth > max_file_depth_short_circuit
        ):
            # This is a short-circuit to prevent a potential never-ending recursive analysis from using up a user's
            # quota for the Hatching service. More info in the service_manifest.yml
            # Ideally, this check would also include the ignore_dynamic_recursion_prevention submission parameter, but
            # it is not available to query against.
            res = Result()
            res_section = ResultTextSection("Max-File-Depth Reached")
            res_section.add_line(
                "Max file depth reached on this submission. This file will not be submitted to Hatching for analysis."
            )
            res.add_section(res_section)
            request.result = res

        else:
            ontres = OntologyResults(service_name=SERVICE_NAME)

            # Determine the VM profiles to submit to
            vm_profiles = self._determine_vm_profiles_to_use(
                self.service_request.get_param("vm_profile")
            )

            # submit the sample
            sample_id = self._submit_file(vm_profiles)

            if sample_id:
                # wait for the report to be completed
                self._poll_is_analysis_completed(sample_id)

                # get the Hatching results
                hatching_results = self._get_hatching_submission_results(sample_id)

                # Generate the result
                hatching_result = HatchingResult(
                    hatching_results=hatching_results,
                    ontres=ontres,
                    web_url=self.config.get("host_config", {}).get("web_url"),
                    sample_id=sample_id,
                    safelist=self.safelist,
                ).generate_result()

                # Handle any dumped artifacts
                artifact_section = self._handle_dumped_artifacts(
                    triage_reports=hatching_results.get("triage_reports", []),
                    analyze_extracted_memory_dumps=self.service_request.get_param(
                        "analyze_extracted_memory_dumps"
                    ),
                )
                if artifact_section:
                    hatching_result.add_section(artifact_section)

                request.result = hatching_result

                # Associate the dynamic sandbox related ontologies
                ontres.preprocess_ontology()
                attach_dynamic_ontology(self, ontres)

    def _auto_detect_vm_platform(self, file_type: str) -> str:
        """Auto detect the vm platform based on the AL4 defined file type.

        Args:
            file_type (str): AL4 file type. e.g. executable/windows/pe64

        Returns:
            str: platform: windows|linux|macos|android|default
                This value must match the config.vm_profile_autodetect_map keys.
        """
        if file_type:
            if "windows" in file_type:
                return VMPlatform.WINDOWS.value
            elif "linux" in file_type:
                return VMPlatform.LINUX.value
            elif "mach-o" in file_type:
                return VMPlatform.MACOS.value
            elif "android" in file_type:
                return VMPlatform.ANDROID.value

        return VMPlatform.DEFAULT.value

    def _build_dumped_artifacts(
        self, triage_reports: List[Dict[str, Any]], analyze_extracted_memory_dumps: bool
    ) -> List[Dict[str, Any]]:
        """Generate a list of filtered artifacts that were dumped from the triage reports and include any pcaps.

        Args:
            triage_reports (triage_reports: List[Dict[str, Any]],): Hatching results for dynamic triage reports
            analyze_extracted_memory_dumps (bool): indicate whether the memory dumps in dumped artifacts should be added
                back to the pipeline for analysis or simply added as a suplementary file(s).

        Returns:
            List[Dict[str, Any]]: list of artifact dicts
                This structure is what is needed downstream by the OntologyResults.handle_artifacts().

                For clarity, the to_be_extracted attribute determines whether the file will be added back to the AL4
                pipeline for analysis vs just being a supplementary file that is attached to the results but not
                analyzed.
                [
                    {
                        "name": str
                        "path": str
                        "description": str
                        "to_be_extracted": bool
                        "hatching_api": {
                            "sample_id": hatching sample id,
                            "task_name": hatching behavioral task id
                            "resource_name": resource name used to download artifact from hatching
                        }
                    }
                ]
        """
        artifacts = []

        # The hatching_api element is added to each artifact for use in a subsequent step for downloading the artifact
        # from the Hatching API

        for rpt in triage_reports or []:
            # The 'extracted' key seems to represent malware extracted configs.
            # The associated file should be in the 'dumped' entries if it is separate from the main file and available.

            for item in rpt.get("dumped", []):
                # do not add duplicates
                artifact = {
                    "name": item.get("name"),
                    "path": None,
                    "description": item.get("name"),
                    "to_be_extracted": self._is_dump_file_to_be_added_to_pipeline(
                        file_name=item.get("name"),
                        dump_origin=item.get("origin", None),
                        analyze_extracted_memory_dumps=analyze_extracted_memory_dumps,
                    ),
                    "hatching_api": {
                        "sample_id": rpt.get("sample", {}).get("id"),
                        "task_name": rpt.get("task_name"),
                        "resource_name": item.get("name"),
                    },
                }

                if artifact not in artifacts:
                    artifacts.append(artifact)

            # Add the pcap
            pcap_name = f"{rpt.get('task_name')}.pcapng"
            artifacts.append(
                {
                    "name": pcap_name,
                    "path": None,
                    "description": pcap_name,
                    "to_be_extracted": True,
                    "hatching_api": {
                        "sample_id": rpt.get("sample", {}).get("id"),
                        "task_name": rpt.get("task_name"),
                        "resource_name": "dump.pcapng",
                    },
                }
            )

        return artifacts

    def _determine_vm_profiles_to_use(self, user_selected_vm_profile: str) -> List[str]:
        """Determine the Hatching VM Profiles that will be used during for a given file submission.

        Args:
            user_selected_vm_profile (str): The user-selected VM profile.

        Raises:
            ValueError: If the profile is not defined in the available vm profile list as defined by the vm_profile
                config in submission_params.

        Returns:
            List[str]: A list of Hatching VM profiles to submit to.
                The user may select a given profile. That user selection is mapped in the service_manifest config which
                may point to 1..* Hatching VM profiles depending on how the administrator has configured the system.

                e.g. 'windows' may have multiple Hatching VM profiles associated.

                See config.vm_profile_autodetect_map
        """
        selected_vm_profiles = []

        if user_selected_vm_profile == "auto-detect-platform":
            platform = self._auto_detect_vm_platform(
                file_type=self.service_request.file_type
            )

            if platform in self.config.get("vm_profile_autodetect_map"):
                selected_vm_profiles = self.config.get("vm_profile_autodetect_map").get(
                    platform
                )
            else:
                # Use the default platform when the platform is not configured.
                # e.g. An admin purposefully does not want the Android platform configured.
                selected_vm_profiles = self.config.get("vm_profile_autodetect_map").get(
                    VMPlatform.DEFAULT.value
                )
        else:
            for sub_param in self.service_attributes.submission_params:
                if sub_param.name == "vm_profile":
                    if user_selected_vm_profile in sub_param.list:
                        selected_vm_profiles.append(user_selected_vm_profile)
                        break

            if not selected_vm_profiles:
                raise ValueError(
                    "Invalid value used in the submission parameter: vm_profile."
                )

        return selected_vm_profiles

    def _download_artifact(self, artifact: Dict[str, Any]) -> str:
        """Download the artifact from Hatching.

        Args:
            artifacts (Dict[str, Any]): artifact dict

        Returns:
            str: file path to downloaded file
        """
        fp = os.path.join(
            self.temp_extracted_files_dir, artifact.get("name", str(uuid.uuid4()))
        )
        fp_dir = os.path.dirname(fp)

        if not os.path.exists(fp_dir):
            os.makedirs(fp_dir)

        with open(fp, "wb") as f:
            f.write(
                self.triage_client.sample_task_file(
                    artifact.get("hatching_api", {}).get("sample_id"),
                    artifact.get("hatching_api", {}).get("task_name"),
                    artifact.get("hatching_api", {}).get("resource_name"),
                )
            )

        return fp

    def _get_hatching_submission_results(self, sample_id: str) -> Dict[str, Any]:
        """Aggregate the results from the hatching submission.

        Args:
            sample_id (str): Hatching Sample ID

        Raises:
            MissingParamException: if sample_id not passed in

        Returns:
            Dict[str, Any]: Aggregated results dict
                {
                    "overview": {},
                    "static_report": {},
                    "triage_reports": [],
                }
        """
        if not sample_id:
            raise MissingParamException("sample_id was not specified.")

        results: Dict[str, Any] = {
            "overview": {},
            "static_report": {},
            "triage_reports": [],
        }

        # Get the high level overview
        overview = self._get_hatching_submission_results_overview(sample_id)
        if overview:
            results["overview"] = overview

        # Get the static report
        static_report = self._get_hatching_submission_results_static_report(sample_id)
        if static_report:
            results["static_report"] = static_report

        # Get triage reports for each task
        triage_reports = []
        for task in results.get("overview", {}).get("tasks"):
            # This is only available for behavioral tasks
            if task.get("kind") == "behavioral":
                task_id = task.get("name")
                rpt = self._get_hatching_submission_results_triage_report(
                    sample_id, task_id
                )
                if rpt:
                    rpt["task_name"] = task_id
                    triage_reports.append(rpt)
        results["triage_reports"] = triage_reports

        return results

    @retry(
        wait_fixed=REPORT_RETRIEVAL_RETRY_DELAY * 1000,
        retry_on_result=_retry_on_none,
        stop_max_attempt_number=2,
    )
    def _get_hatching_submission_results_overview(
        self, sample_id: str
    ) -> Optional[Dict[str, Any]]:
        """Get the overview report for a given submission.

        Args:
            sample_id (str): Sample ID

        Raises:
            RetryError: if stop_max_attempt_number is exceeded

        Returns:
            Dict[str, Any]: Hatching submission Overview Report
                Ref: https://tria.ge/docs/cloud-api/overview-report/
        """
        try:
            return self.triage_client.overview_report(sample_id)
        except ServerError:
            self.log.exception(
                "Exception retrieving the overview report for sample_id: %s", sample_id
            )

        return None

    @retry(
        wait_fixed=REPORT_RETRIEVAL_RETRY_DELAY * 1000,
        retry_on_result=_retry_on_none,
        stop_max_attempt_number=2,
    )
    def _get_hatching_submission_results_static_report(
        self, sample_id: str
    ) -> Optional[Dict[str, Any]]:
        """Get the static report for a given submission.

        Args:
            sample_id (str): Sample ID

        Raises:
            RetryError: if stop_max_attempt_number is exceeded

        Returns:
            Dict[str, Any]: Hatching submission Static Report
                Ref: https://tria.ge/docs/cloud-api/static-report/
        """
        try:
            return self.triage_client.static_report(sample_id)
        except ServerError:
            self.log.exception(
                "Excpetion retrieving the static report for sample_id: %s", sample_id
            )

        return None

    @retry(
        wait_fixed=REPORT_RETRIEVAL_RETRY_DELAY * 1000,
        retry_on_result=_retry_on_none,
        stop_max_attempt_number=2,
    )
    def _get_hatching_submission_results_triage_report(
        self, sample_id: str, task_id: str
    ) -> Optional[Dict[str, Any]]:
        """Get the dynamic analysis triage report for a given sample.

        Args:
            sample_id (str): Sample ID
            task_id (str): The specific dynamic analysis task.

        Raises:
            RetryError: if stop_max_attempt_number is exceeded

        Returns:
            Dict[str, Any]: Hatching submission Triage Report
                Ref: https://tria.ge/docs/cloud-api/dynamic-report/
        """
        try:
            return self.triage_client.task_report(sample_id, task_id)
        except ServerError:
            self.log.exception(
                "Exception retrieving the dynamic triage report for sample_id: %s  task_id: %s",
                sample_id,
                task_id,
            )

        return None

    def _handle_dumped_artifacts(
        self, triage_reports: List[Dict[str, Any]], analyze_extracted_memory_dumps: bool
    ) -> Optional[ResultSection]:
        """Handle any dumped artifacts that come back from the Hatching analysis.

        Args:
            triage_reports (List[Dict[str, Any]]): Hatching results for dynamic triage reports
            analyze_extracted_memory_dumps (bool): indicate whether the memory dumps in dumped artifacts should be added
                back to the pipeline for analysis or simply added as a suplementary file(s).

        Returns:
            Optional[ResultSection]: A ResultSection or None
        """
        # build the artifacts dumped from the Hatching execution
        artifacts = self._build_dumped_artifacts(
            triage_reports, analyze_extracted_memory_dumps
        )

        # download all artifacts from hatching. Even if it's not being added back to the pipeline for analysis. Those
        # files will just be added as supplementary files.
        for artifact in artifacts:
            # update the artifact.path with local file path the file was downloaded to
            artifact["path"] = self._download_artifact(artifact)

        # Add extracted artifacts. Add them to the pipeline if indicated in the artifact.
        artifact_section = OntologyResults.handle_artifacts(
            artifacts, self.service_request, collapsed=True, parent_relation="DYNAMIC"
        )

        # Do not expect a ResultSection to come back. Currently this is only creating a ResultSection for hollows-hunter
        # dumps which are not found in Hatching.
        if artifact_section:
            return artifact_section

        return None

    def _is_dump_file_to_be_added_to_pipeline(
        self,
        file_name: str,
        dump_origin: str,
        analyze_extracted_memory_dumps: bool = False,
    ) -> bool:
        """Determine if the dump file is to be added back to the pipeline for analysis.

        Args:
            file_name (str):
            dump_origin (str, optional): dump origin from the hatching dumped file structure. Defaults to None.
            analyze_extracted_memory_dumps (bool, optional): indicate whether the memory dumps in dumped artifacts
                should be added back to the pipeline for analysis or simply added as a suplementary file(s).

        Returns:
            bool: _description_
        """
        if file_name:
            if file_name.startswith("memory/") or file_name.endswith(".dmp"):
                # Excluding memory dumps with an origin=exception
                if analyze_extracted_memory_dumps and dump_origin != "exception":
                    return True
                else:
                    return False
            else:
                return True

        return False

    @retry(
        wait_fixed=SUBMISSION_POLL_DELAY * 1000,
        retry_on_result=_retry_on_false,
    )
    def _poll_is_analysis_completed(self, sample_id: str) -> bool:
        """Poll the Hatching API to determine whether an analysis is completed.

        This will continue indefinitely until the service times out.

        Args:
            sample_id (str): Hatching Sample ID

        Returns:
            bool:
        """
        sample_status_resp = self.triage_client.sample_by_id(sample_id)

        status = sample_status_resp.get("status", None)

        # possible status values: scheduled, running, reported
        if status == "reported":
            return True

        return False

    def _reinit_temp_dir(self) -> None:
        """Re-initialize the temp directory used to download files."""
        if os.path.exists(self.temp_extracted_files_dir):
            shutil.rmtree(self.temp_extracted_files_dir)

        # reinit dir
        os.mkdir(self.temp_extracted_files_dir)

    def _submit_file(self, vm_profiles: List[str]) -> str:
        """Submit the file to Hatching.

        Args:
            vm_profiles (List[str]): List of vm-profile names. The profile(s) must be defined in Hatching.

        Raises:
            FailedSubmissionException:

        Returns:
            str: Hatching Sample ID
        """
        profiles_param = []
        for prof in vm_profiles:
            profiles_param.append({"profile": prof})

        with open(self.service_request.file_path, "rb") as fh:
            sub_resp = self.triage_client.submit_sample_file(
                self.service_request.task.file_name,
                fh,
                interactive=False,
                profiles=profiles_param,
            )

        sample_id = sub_resp.get("id", None)

        if not sample_id:
            self.log.error(
                "Invalid response received from the Hatching API while submitting a file for analysis.",
                extra=json.dumps(sub_resp),
            )
            raise FailedSubmissionException()
        return sample_id

    def _validate_config(self) -> bool:
        """Validate the service_manifest config section is defined properly.

        The vm_profile_autodetect_map config is validated to have the appropriate keys and value types.

        Raises:
            InvalidConfigurationException: If an invalid configuration is detected it will raise this error.

        Returns:
            bool: is config valid
        """
        vm_autodetect_cfg = self.config.get("vm_profile_autodetect_map", {})

        #
        # Validate the required keys are in place
        required_keys = [
            VMPlatform.DEFAULT.value,
        ]

        # validate all keys are represented in the config.vm_profile_autodetect_map
        has_required_keys = all(k in vm_autodetect_cfg.keys() for k in required_keys)
        if not has_required_keys:
            raise InvalidConfigurationException(
                "The service_manifest config key is not configured properly. The vm_profile_autodetect_map key must "
                f"have the following required keys: {required_keys}"
            )

        #
        # Validate that all keys present are either in the optional_keys ore required_keys
        optional_keys = [
            VMPlatform.WINDOWS.value,
            VMPlatform.LINUX.value,
            VMPlatform.MACOS.value,
            VMPlatform.ANDROID.value,
        ]
        keys_valid = all(
            k in vm_autodetect_cfg.keys() for k in required_keys + optional_keys
        )
        if not keys_valid:
            raise InvalidConfigurationException(
                "The service_manifest config key is not configured properly. The vm_profile_autodetect_map key must "
                "has unexpected keys present. It can only have the required keys: "
                f"{required_keys} and optional keys: {optional_keys}"
            )

        #
        # validate the values for all keys are the expected list type with at least one value
        vals_valid = all(
            isinstance(v, list) and len(v) > 0 for v in vm_autodetect_cfg.values()
        )
        if not vals_valid:
            raise InvalidConfigurationException(
                "The service_manifest config.vm_profile_autodetect_map key has unexpected values. Each key must have a "
                "list type with at least one value in the list."
            )

        return True

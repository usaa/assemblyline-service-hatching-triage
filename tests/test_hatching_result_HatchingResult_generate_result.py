import pytest
import json
import logging as log

from assemblyline_v4_service.common.result import BODY_FORMAT
from assemblyline_service_utilities.common.dynamic_service_helper import OntologyResults
from hatching.hatching import SERVICE_NAME
from hatching.hatching_result import HatchingResult

from .utils import (
    hatching_result_with_imported_results,
    hatching_result_instance,
    find_result_section,
)


@pytest.mark.parametrize(
    "hatching_result_with_imported_results",
    [
        (
            {
                "overview_file": "api_samples/230815-aaabbbccc1-overview.json",
                "static_report_file": "api_samples/230815-aaabbbccc1-static.json",
                "triage_report_files": [
                    "api_samples/230815-aaabbbccc1-rpt-triage-behavioral1.json",
                    "api_samples/230815-aaabbbccc1-rpt-triage-behavioral2.json",
                ],
            },
            "230815-aaabbbccc1",
        )
    ],
    indirect=["hatching_result_with_imported_results"],
)
def test_generate_result(
    hatching_result_with_imported_results: hatching_result_with_imported_results,
):
    """Validate the Result is built with the appropriate sections.

    Expects: Overview, Link, Static Analysis, Dynamic Analysis win7, win10
    """
    result = hatching_result_with_imported_results.generate_result()

    assert result is not None

    # for sec in result.sections:
    #    log.warning("%s - %s", sec.title_text, sec.body_format)

    # log.warning(result.sections)
    assert len(result.sections) == 5

    #
    section = find_result_section(result.sections, "Results Overview")
    assert section is not None
    assert section.title_text == "Results Overview"
    assert section.body_format == BODY_FORMAT.KEY_VALUE

    #
    section = find_result_section(result.sections, "Link to Hatching Triage Analysis")
    assert section is not None
    assert section.title_text == "Link to Hatching Triage Analysis"
    assert section.body_format == BODY_FORMAT.URL

    #
    section = find_result_section(result.sections, "Static Analysis")
    assert section is not None
    assert section.title_text == "Static Analysis"
    assert section.body_format == BODY_FORMAT.TEXT

    #
    section = find_result_section(
        result.sections, "Dynamic Analysis Platform: windows7_x64"
    )
    assert section is not None
    assert section.title_text == "Dynamic Analysis Platform: windows7_x64"
    assert section.body_format == BODY_FORMAT.TEXT

    #
    section = find_result_section(
        result.sections, "Dynamic Analysis Platform: windows10-2004_x64"
    )
    assert section is not None
    assert section.title_text == "Dynamic Analysis Platform: windows10-2004_x64"
    assert section.body_format == BODY_FORMAT.TEXT


@pytest.mark.parametrize(
    "hatching_result_with_imported_results",
    [
        (
            {
                "overview_file": "api_samples/230815-aaabbbccc1-overview.json",
                "static_report_file": "api_samples/230815-aaabbbccc1-static.json",
                "triage_report_files": [],
            },
            "230815-aaabbbccc1",
        )
    ],
    indirect=["hatching_result_with_imported_results"],
)
def test_with_no_dyn_reports(
    hatching_result_with_imported_results: hatching_result_with_imported_results,
):
    """Validate the Result is built with the appropriate sections.

    Expects: Overview, Link, Static Analysis
    """
    result = hatching_result_with_imported_results.generate_result()

    assert result is not None

    # for sec in result.sections:
    #    log.warning("%s - %s", sec.title_text, sec.body_format)

    # log.warning(result.sections)
    assert len(result.sections) == 3

    #
    section = find_result_section(result.sections, "Results Overview")
    assert section is not None
    assert section.title_text == "Results Overview"
    assert section.body_format == BODY_FORMAT.KEY_VALUE

    #
    section = find_result_section(result.sections, "Link to Hatching Triage Analysis")
    assert section is not None
    assert section.title_text == "Link to Hatching Triage Analysis"
    assert section.body_format == BODY_FORMAT.URL

    #
    section = find_result_section(result.sections, "Static Analysis")
    assert section is not None
    assert section.title_text == "Static Analysis"
    assert section.body_format == BODY_FORMAT.TEXT


def test_when_no_triage_rpt(
    hatching_result_instance: hatching_result_instance,
):
    """Validate the result has no sections when no data present."""
    hatching_result_instance.sample_id = None  # overriding the default
    hatching_result_instance.hatching_results = {}
    result = hatching_result_instance.generate_result()
    assert result.sections == []

    hatching_result_instance.hatching_results = None
    result = hatching_result_instance.generate_result()
    assert result.sections == []

    # expected structure, but no data
    hatching_result_instance.hatching_results = {
        "overview": {},
        "static_report": {},
        "triage_reports": [],
    }
    result = hatching_result_instance.generate_result()
    assert result.sections == []


def test_ontology_results():
    """Validate the ontology results are created properly after generating the full results"""

    # abbreviated view of the hatching api results for overview, static, and triage reports
    hatching_results = {
        "overview": {
            "sample": {
                "score": 10,
                "created": "2023-09-22T21:47:33Z",
                "completed": "2023-09-22T21:48:43Z",
            },
            "tasks": [
                {
                    "kind": "behavioral",
                    "task_name": "vm-profile-win",
                },
                {
                    "kind": "static",
                },
            ],
            "analysis": {
                "score": 10,
            },
        },
        "static_report": {
            "signatures": [
                {
                    "name": "Test Sig 1",
                    "score": 10,
                    "tags": ["family:test"],
                    "ttp": [
                        "T1008",
                    ],
                    "desc": "test description 1",
                },
            ],
        },
        "triage_reports": [
            {
                "analysis": {
                    "score": 10,
                    "submitted": "2023-09-22T21:47:33Z",
                    "reported": "2023-09-22T21:48:43Z",
                    "platform": "windows10-2004_x64",
                },
                "extracted": [],
                "network": {},
                "signatures": [
                    {
                        "name": "Test Sig 2",
                        "score": 10,
                        "tags": ["family:test"],
                        "ttp": ["T1006", "T1552.001"],
                        "desc": "test description 2",
                    },
                ],
                "task_name": "vm-profile-win",
                "version": "0.3.0",
            }
        ],
    }

    ontres_inp = OntologyResults(service_name=SERVICE_NAME)
    sample_id = "230815-xxxyyyzzz1"

    hatching_result = HatchingResult(
        hatching_results=hatching_results,
        ontres=ontres_inp,
        web_url="http://test.local",
        sample_id=sample_id,
        safelist={},
    )
    hatching_result.generate_result()

    ontres = hatching_result.ontres

    #
    # Validate signatures in ontres
    sig_primitives = [sig.as_primitives() for sig in ontres.signatures]
    # log.warning(sig_primitives)
    assert sig_primitives == [
        {
            "objectid": {
                "tag": "CUCKOO.Test Sig 1",
                "ontology_id": "signature_5OqJRcAIh2lvwvmMVgjM0P",
                "service_name": "HATCHING",
                "guid": None,
                "treeid": None,
                "processtree": None,
                "time_observed": None,
                "session": None,
            },
            "name": "Test Sig 1",
            "type": "CUCKOO",
            "attributes": [],
            "classification": "TLP:C",
            "attacks": [
                {
                    "attack_id": "T1008",
                    "pattern": "Fallback Channels",
                    "categories": ["command-and-control"],
                }
            ],
            "actors": [],
            "malware_families": ["test"],
        },
        {
            "objectid": {
                "tag": "CUCKOO.Test Sig 2",
                "ontology_id": "signature_zDSL8muqbwXqwJvIr3I3L",
                "service_name": "HATCHING",
                "guid": None,
                "treeid": None,
                "processtree": None,
                "time_observed": None,
                "session": None,
            },
            "name": "Test Sig 2",
            "type": "CUCKOO",
            "attributes": [],
            "classification": "TLP:C",
            "attacks": [
                {
                    "attack_id": "T1006",
                    "pattern": "Direct Volume Access",
                    "categories": ["defense-evasion"],
                },
                {
                    "attack_id": "T1552.001",
                    "pattern": "Credentials In Files",
                    "categories": ["credential-access"],
                },
            ],
            "actors": [],
            "malware_families": ["test"],
        },
    ]

    #
    # Validate sandbox in ontres
    sandbox_primitives = [sb.as_primitives() for sb in ontres.sandboxes]
    # remove the objectid.session as this will be unique per run
    for sbp in sandbox_primitives:
        sbp.get("objectid").pop("session")
    # log.warning(sandbox_primitives)
    assert sandbox_primitives == [
        {
            "objectid": {
                "tag": "HATCHING",
                "ontology_id": "sandbox_3AputckCwGvfSjy1bSwsVr",
                "service_name": "HATCHING",
                "guid": None,
                "treeid": None,
                "processtree": None,
                "time_observed": None,
                # "session": "3VoLjGVTQUpc0IYrmfoL3o",
            },
            "analysis_metadata": {
                "start_time": "2023-09-22T21:47:33Z",
                "task_id": None,
                "end_time": "2023-09-22T21:48:43Z",
                "routing": None,
                "machine_metadata": None,
            },
            "sandbox_name": "HATCHING",
            "sandbox_version": "0.3.0",
        }
    ]

    # The following ontres results are not available yet
    assert len(ontres.netflows) == 0
    assert len(ontres.dns_netflows) == 0
    assert len(ontres.http_netflows) == 0


@pytest.mark.parametrize(
    "hatching_result_with_imported_results",
    [
        (
            {
                "overview_file": "api_samples/230815-aaabbbccc1-overview.json",
                "static_report_file": "api_samples/230815-aaabbbccc1-static.json",
                "triage_report_files": [
                    "api_samples/230815-aaabbbccc1-rpt-triage-behavioral1.json",
                    "api_samples/230815-aaabbbccc1-rpt-triage-behavioral2.json",
                ],
            },
            "230815-aaabbbccc1",
        )
    ],
    indirect=["hatching_result_with_imported_results"],
)
def test_validate_ontology_results_with_full_api_results(
    hatching_result_with_imported_results: hatching_result_with_imported_results,
):
    """Validate the ontology results are created properly after generating the full results
    from a full set of api results
    """

    result = hatching_result_with_imported_results.generate_result()

    ontres = hatching_result_with_imported_results.ontres

    #
    # Validate signatures in ontres
    sig_primitives = [sig.as_primitives() for sig in ontres.signatures]
    # log.warning(sig_primitives)
    assert sig_primitives == [
        {
            "objectid": {
                "tag": "CUCKOO.Ramnit family",
                "ontology_id": "signature_XNT65I1kfWuEUM7DoPIy7",
                "service_name": "HATCHING",
                "guid": None,
                "treeid": None,
                "processtree": None,
                "time_observed": None,
                "session": None,
            },
            "name": "Ramnit family",
            "type": "CUCKOO",
            "attributes": [],
            "classification": "TLP:C",
            "attacks": [],
            "actors": [],
            "malware_families": ["ramnit"],
        },
        {
            "objectid": {
                "tag": "CUCKOO.UPX packed file",
                "ontology_id": "signature_2WBNRQ6nOa6MrX3mTbIw3W",
                "service_name": "HATCHING",
                "guid": None,
                "treeid": None,
                "processtree": None,
                "time_observed": None,
                "session": None,
            },
            "name": "UPX packed file",
            "type": "CUCKOO",
            "attributes": [],
            "classification": "TLP:C",
            "attacks": [],
            "actors": [],
            "malware_families": [],
        },
        {
            "objectid": {
                "tag": "CUCKOO.Unsigned PE",
                "ontology_id": "signature_6cWvmYVX9zrtB4SPk18u6p",
                "service_name": "HATCHING",
                "guid": None,
                "treeid": None,
                "processtree": None,
                "time_observed": None,
                "session": None,
            },
            "name": "Unsigned PE",
            "type": "CUCKOO",
            "attributes": [],
            "classification": "TLP:C",
            "attacks": [],
            "actors": [],
            "malware_families": [],
        },
        {
            "objectid": {
                "tag": "CUCKOO.Ramnit",
                "ontology_id": "signature_2MK8f275umc6k37O8n2ecz",
                "service_name": "HATCHING",
                "guid": None,
                "treeid": None,
                "processtree": None,
                "time_observed": None,
                "session": None,
            },
            "name": "Ramnit",
            "type": "CUCKOO",
            "attributes": [],
            "classification": "TLP:C",
            "attacks": [],
            "actors": [],
            "malware_families": ["ramnit"],
        },
        {
            "objectid": {
                "tag": "CUCKOO.Loads dropped DLL",
                "ontology_id": "signature_6VBkuEvA8oYmUkpdY3Dwpn",
                "service_name": "HATCHING",
                "guid": None,
                "treeid": None,
                "processtree": None,
                "time_observed": None,
                "session": None,
            },
            "name": "Loads dropped DLL",
            "type": "CUCKOO",
            "attributes": [],
            "classification": "TLP:C",
            "attacks": [],
            "actors": [],
            "malware_families": [],
        },
        {
            "objectid": {
                "tag": "CUCKOO.UPX packed file",
                "ontology_id": "signature_2WBNRQ6nOa6MrX3mTbIw3W",
                "service_name": "HATCHING",
                "guid": None,
                "treeid": None,
                "processtree": None,
                "time_observed": None,
                "session": None,
            },
            "name": "UPX packed file",
            "type": "CUCKOO",
            "attributes": [],
            "classification": "TLP:C",
            "attacks": [],
            "actors": [],
            "malware_families": [],
        },
        {
            "objectid": {
                "tag": "CUCKOO.Program crash",
                "ontology_id": "signature_3MHG7VYyDqUBhgQm13TUTk",
                "service_name": "HATCHING",
                "guid": None,
                "treeid": None,
                "processtree": None,
                "time_observed": None,
                "session": None,
            },
            "name": "Program crash",
            "type": "CUCKOO",
            "attributes": [],
            "classification": "TLP:C",
            "attacks": [],
            "actors": [],
            "malware_families": [],
        },
        {
            "objectid": {
                "tag": "CUCKOO.Ramnit",
                "ontology_id": "signature_2MK8f275umc6k37O8n2ecz",
                "service_name": "HATCHING",
                "guid": None,
                "treeid": None,
                "processtree": None,
                "time_observed": None,
                "session": None,
            },
            "name": "Ramnit",
            "type": "CUCKOO",
            "attributes": [],
            "classification": "TLP:C",
            "attacks": [],
            "actors": [],
            "malware_families": ["ramnit"],
        },
        {
            "objectid": {
                "tag": "CUCKOO.Loads dropped DLL",
                "ontology_id": "signature_6VBkuEvA8oYmUkpdY3Dwpn",
                "service_name": "HATCHING",
                "guid": None,
                "treeid": None,
                "processtree": None,
                "time_observed": None,
                "session": None,
            },
            "name": "Loads dropped DLL",
            "type": "CUCKOO",
            "attributes": [],
            "classification": "TLP:C",
            "attacks": [],
            "actors": [],
            "malware_families": [],
        },
        {
            "objectid": {
                "tag": "CUCKOO.UPX packed file",
                "ontology_id": "signature_2WBNRQ6nOa6MrX3mTbIw3W",
                "service_name": "HATCHING",
                "guid": None,
                "treeid": None,
                "processtree": None,
                "time_observed": None,
                "session": None,
            },
            "name": "UPX packed file",
            "type": "CUCKOO",
            "attributes": [],
            "classification": "TLP:C",
            "attacks": [],
            "actors": [],
            "malware_families": [],
        },
        {
            "objectid": {
                "tag": "CUCKOO.Program crash",
                "ontology_id": "signature_3MHG7VYyDqUBhgQm13TUTk",
                "service_name": "HATCHING",
                "guid": None,
                "treeid": None,
                "processtree": None,
                "time_observed": None,
                "session": None,
            },
            "name": "Program crash",
            "type": "CUCKOO",
            "attributes": [],
            "classification": "TLP:C",
            "attacks": [],
            "actors": [],
            "malware_families": [],
        },
    ]

    #
    # Validate sandbox in ontres
    sandbox_primitives = [sb.as_primitives() for sb in ontres.sandboxes]
    for sbp in sandbox_primitives:
        sbp.get("objectid").pop("session")
    #log.warning(sandbox_primitives)
    assert sandbox_primitives == [
        {
            "objectid": {
                "tag": "HATCHING",
                "ontology_id": "sandbox_4uhu9DsjSZxgSqHkaF5ubF",
                "service_name": "HATCHING",
                "guid": None,
                "treeid": None,
                "processtree": None,
                "time_observed": None,
                # "session": "1BoXkDCPJNvJQvpU8kNn4T",
            },
            "analysis_metadata": {
                "start_time": "2023-08-15T12:46:41Z",
                "task_id": None,
                "end_time": "2023-08-15T12:47:18Z",
                "routing": None,
                "machine_metadata": None,
            },
            "sandbox_name": "HATCHING",
            "sandbox_version": "0.3.0",
        },
        {
            "objectid": {
                "tag": "HATCHING",
                "ontology_id": "sandbox_4uhu9DsjSZxgSqHkaF5ubF",
                "service_name": "HATCHING",
                "guid": None,
                "treeid": None,
                "processtree": None,
                "time_observed": None,
                # "session": "2Rz6K1gEb7vix53Ng54iXM",
            },
            "analysis_metadata": {
                "start_time": "2023-08-15T12:46:41Z",
                "task_id": None,
                "end_time": "2023-08-15T12:47:18Z",
                "routing": None,
                "machine_metadata": None,
            },
            "sandbox_name": "HATCHING",
            "sandbox_version": "0.3.0",
        },
    ]

    assert len(ontres.processes) == 2

    # The following ontres results are not available yet
    assert len(ontres.netflows) == 0
    assert len(ontres.dns_netflows) == 0
    assert len(ontres.http_netflows) == 0

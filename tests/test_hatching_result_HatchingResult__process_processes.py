import pytest
import json
import logging as log

import datetime

from unittest import mock

from assemblyline_v4_service.common.result import BODY_FORMAT
from .utils import hatching_result_instance, find_result_section

ontres_dyn_kwargs = {
    "task_name": "test-profile-1",
    "start_time": "2023-09-19T18:52:26Z",
    "end_time": "2023-09-19T18:54:46Z",
    "platform": "windows10-2004_x64",
    "version": "0.3.0",
}


def test_process_processes(hatching_result_instance: hatching_result_instance, mocker):
    """
    Validate the processes are added to the ontres and structured properly.
    """

    # this will create a sandbox instance on ontres.sandboxes[] which is expected by _build_process_section()
    hatching_result_instance._update_ontres_for_dynamic_result_info_section(
        **ontres_dyn_kwargs
    )

    # Abbreviated example data created from a dynamic analysis triage report: .processes key
    hatching_procs = [
        {
            "procid": 80,
            "procid_parent": 68,
            "pid": 2380,
            "ppid": 676,
            "cmd": "C:\\Users\\Admin\\AppData\\Local\\Temp\\sample.exe",
            "image": "C:\\Users\\Admin\\AppData\\Local\\Temp\\sample.exe",
            "orig": False,
            "started": 1156,
            "terminated": 3563,
        },
        {
            "procid": 81,
            "procid_parent": 80,
            "pid": 4780,
            "ppid": 2380,
            "cmd": "c:\\windows\\resources\\themes\\explorer.exe",
            "image": "\\??\\c:\\windows\\resources\\themes\\explorer.exe",
            "orig": False,
            "started": 2750,
        },
        {
            "procid": 82,
            "procid_parent": 81,
            "pid": 1452,
            "ppid": 4780,
            "cmd": "c:\\windows\\resources\\spoolsv.exe SE",
            "image": "\\??\\c:\\windows\\resources\\spoolsv.exe",
            "orig": False,
            "started": 3016,
            "terminated": 3547,
        },
    ]

    with mock.patch("datetime.datetime", wraps=datetime.datetime) as dt:
        dt.utcnow.return_value = datetime.datetime(2024, 1, 1, 0, 0, 0)
        hatching_result_instance._process_processes(hatching_procs=hatching_procs)

    ontres_procs = hatching_result_instance.ontres.get_processes()

    expected_procs_as_primitivces = [
        {
            "objectid": {
                "tag": "?usrtmp\\sample.exe",
                "ontology_id": "process_49VbzzHZhAk1ZS8h9sRihx",
                "service_name": "HATCHING",
                # "guid": "{C7878C45-AFAA-4089-B9BE-5F51D266B446}",
                "treeid": None,
                "processtree": None,
                "time_observed": "2024-01-01 00:00:01.156000",
            },
            "image": "C:\\Users\\Admin\\AppData\\Local\\Temp\\sample.exe",
            "start_time": "2024-01-01 00:00:01.156000",
            "pobjectid": None,
            "pimage": None,
            "pcommand_line": None,
            "ppid": 676,
            "pid": 2380,
            "command_line": "C:\\Users\\Admin\\AppData\\Local\\Temp\\sample.exe",
            "end_time": "2024-01-01 00:00:03.563000",
            "integrity_level": None,
            "image_hash": None,
            "original_file_name": None,
            "loaded_modules": None,
            "services_involved": None
        },
        {
            "objectid": {
                "tag": "\\??\\c:\\windows\\resources\\themes\\explorer.exe",
                "ontology_id": "process_1VLVVNOMqtqCWpiuPP7bAk",
                "service_name": "HATCHING",
                # "guid": "{DF844777-CE5C-4554-A261-82A4B5D6A318}",
                "treeid": None,
                "processtree": None,
                "time_observed": "2024-01-01 00:00:02.750000",
            },
            "image": "\\??\\c:\\windows\\resources\\themes\\explorer.exe",
            "start_time": "2024-01-01 00:00:02.750000",
            "pobjectid": {
                "tag": "?usrtmp\\sample.exe",
                "ontology_id": "process_49VbzzHZhAk1ZS8h9sRihx",
                "service_name": "HATCHING",
                # "guid": "{C7878C45-AFAA-4089-B9BE-5F51D266B446}",
                "treeid": None,
                "processtree": None,
                "time_observed": "2024-01-01 00:00:01.156000",
            },
            "pimage": "C:\\Users\\Admin\\AppData\\Local\\Temp\\sample.exe",
            "pcommand_line": "C:\\Users\\Admin\\AppData\\Local\\Temp\\sample.exe",
            "ppid": 2380,
            "pid": 4780,
            "command_line": "c:\\windows\\resources\\themes\\explorer.exe",
            "end_time": "9999-12-31 23:59:59.999999",
            "integrity_level": None,
            "image_hash": None,
            "original_file_name": None,
            "loaded_modules": None,
            "services_involved": None
        },
        {
            "objectid": {
                "tag": "\\??\\c:\\windows\\resources\\spoolsv.exe",
                "ontology_id": "process_68xHC0GiLpbM8sXDc5zzMr",
                "service_name": "HATCHING",
                # "guid": "{9F71529F-C039-4699-AC14-78FA15721927}",
                "treeid": None,
                "processtree": None,
                "time_observed": "2024-01-01 00:00:03.016000",
            },
            "image": "\\??\\c:\\windows\\resources\\spoolsv.exe",
            "start_time": "2024-01-01 00:00:03.016000",
            "pobjectid": {
                "tag": "\\??\\c:\\windows\\resources\\themes\\explorer.exe",
                "ontology_id": "process_1VLVVNOMqtqCWpiuPP7bAk",
                "service_name": "HATCHING",
                # "guid": "{DF844777-CE5C-4554-A261-82A4B5D6A318}",
                "treeid": None,
                "processtree": None,
                "time_observed": "2024-01-01 00:00:02.750000",
            },
            "pimage": "\\??\\c:\\windows\\resources\\themes\\explorer.exe",
            "pcommand_line": "c:\\windows\\resources\\themes\\explorer.exe",
            "ppid": 4780,
            "pid": 1452,
            "command_line": "c:\\windows\\resources\\spoolsv.exe SE",
            "end_time": "2024-01-01 00:00:03.547000",
            "integrity_level": None,
            "image_hash": None,
            "original_file_name": None,
            "loaded_modules": None,
            "services_involved": None
        },
    ]

    assert len(ontres_procs) == 3

    ontres_procs_as_primitives = [proc.as_primitives() for proc in ontres_procs]
    for procd in ontres_procs_as_primitives:
        # get rid of random session attr and guid
        procd.get("objectid").pop("session")
        procd.get("objectid").pop("guid")
        if procd.get("pobjectid"):
            procd.get("pobjectid").pop("session")
            procd.get("pobjectid").pop("guid")

        # log.warning(procd)
        assert procd in expected_procs_as_primitivces


def test_process_processes_filtered(
    hatching_result_instance: hatching_result_instance, mocker
):
    """
    Validate the processes are filtered properly based on the safelist.
    """

    # this will create a sandbox instance on ontres.sandboxes[] which is expected by _build_process_section()
    hatching_result_instance._update_ontres_for_dynamic_result_info_section(
        **ontres_dyn_kwargs
    )

    # Abbreviated example data created from a dynamic analysis triage report: .processes key
    hatching_procs = [
        {
            "procid": 80,
            "procid_parent": 68,
            "pid": 2380,
            "ppid": 676,
            "cmd": "C:\\Windows\\safe.exe",
            "image": "C:\\Windows\\safe.exe",
            "orig": False,
            "started": 1156,
            "terminated": 3563,
        },
        {
            "procid": 81,
            "procid_parent": 80,
            "pid": 4780,
            "ppid": 2380,
            "cmd": "C:\\Windows\\safe2.exe",
            "image": "C:\\Windows\\safe2.exe",
            "orig": False,
            "started": 2750,
        },
        {
            "procid": 30,
            "procid_parent": 27,
            "pid": 2332,
            "ppid": 2292,
            "cmd": "C:\\Windows\\SysWOW64\\WerFault2.exe",
            "image": "C:\\Windows\\SysWOW64\\WerFault2.exe",
            "orig": False,
            "started": 579,
        },
    ]

    hatching_result_instance.safelist = {
        "regex": {"dynamic.process.command_line": [r"C:\\Windows\\safe\.exe"]},
        "match": {"dynamic.process.file_name": [r"C:\Windows\safe2.exe"]},
    }

    with mock.patch("datetime.datetime", wraps=datetime.datetime) as dt:
        dt.utcnow.return_value = datetime.datetime(2024, 1, 1, 0, 0, 0)
        hatching_result_instance._process_processes(hatching_procs=hatching_procs)

    ontres_procs = hatching_result_instance.ontres.get_processes()

    expected_procs_as_primitivces = [
        {
            "objectid": {
                "tag": "?sys32\\werfault2.exe",
                "ontology_id": "process_26BTvE9P3Hiu8AJI1GwTF7",
                "service_name": "HATCHING",
                "treeid": None,
                "processtree": None,
                "time_observed": "2024-01-01 00:00:00.579000",
            },
            "image": "C:\\Windows\\SysWOW64\\WerFault2.exe",
            "start_time": "2024-01-01 00:00:00.579000",
            "pobjectid": None,
            "pimage": None,
            "pcommand_line": None,
            "ppid": 2292,
            "pid": 2332,
            "command_line": "C:\\Windows\\SysWOW64\\WerFault2.exe",
            "end_time": "9999-12-31 23:59:59.999999",
            "integrity_level": None,
            "image_hash": None,
            "original_file_name": None,
            "loaded_modules": None,
            "services_involved": None
        },
    ]

    assert len(ontres_procs) == 1

    ontres_procs_as_primitives = [proc.as_primitives() for proc in ontres_procs]
    for procd in ontres_procs_as_primitives:
        # get rid of random session attr and guid
        procd.get("objectid").pop("session")
        procd.get("objectid").pop("guid")
        if procd.get("pobjectid"):
            procd.get("pobjectid").pop("session")
            procd.get("pobjectid").pop("guid")

        # log.warning(procd)
        assert procd in expected_procs_as_primitivces


def test_process_processes_missing_and_diff_input(
    hatching_result_instance: hatching_result_instance, mocker
):
    """
    Validate the processes with missing cmd or image props are filtered.
    Also validate proc is in the output when the cmd prop is a list instead of a str.
    """

    # this will create a sandbox instance on ontres.sandboxes[] which is expected by _build_process_section()
    hatching_result_instance._update_ontres_for_dynamic_result_info_section(
        **ontres_dyn_kwargs
    )

    # Abbreviated example data created from a dynamic analysis triage report: .processes key
    hatching_procs = [
        {
            "procid": 80,
            "procid_parent": 68,
            "pid": 2380,
            "ppid": 676,
            "cmd": "C:\\Windows\\malware.exe",
            "image": "C:\\Windows\\malware.exe",
            "orig": False,
            "started": 1156,
            "terminated": 3563,
        },
        # missing cmd - filtered
        {
            "procid": 81,
            "procid_parent": 80,
            "pid": 4780,
            "ppid": 2380,
            "cmd": "",
            "image": "C:\\Windows\\child1.exe",
            "orig": False,
            "started": 2750,
        },
        # missing image - filtered
        {
            "procid": 30,
            "procid_parent": 80,
            "pid": 2332,
            "ppid": 2292,
            "cmd": "C:\\Windows\\child2.exe",
            "image": "",
            "orig": False,
            "started": 579,
        },
        # missing image - filtered
        {
            "procid": 31,
            "procid_parent": 80,
            "pid": 2422,
            "ppid": 2380,
            "cmd": "C:\\Windows\\child3.exe",
            "image": None,
            "orig": False,
            "started": 579,
        },
        # missing cmd - filtered
        {
            "procid": 32,
            "procid_parent": 80,
            "pid": 2325,
            "ppid": 2380,
            "cmd": None,
            "image": "C:\\Windows\\child4.exe",
            "orig": False,
            "started": 579,
        },
        # list instead of str for cmd
        {
            "procid": 1,
            "pid": 587,
            "ppid": 576,
            "cmd": ["/tmp/mal2"],
            "image": "/tmp/mal2",
            "orig": False,
            "started": 3300,
        },
        # empty list - filtered
        {
            "procid": 2,
            "pid": 588,
            "ppid": 576,
            "cmd": [],
            "image": "/tmp/mal2",
            "orig": False,
            "started": 3300,
        },
    ]

    hatching_result_instance.safelist = {
        "regex": {"dynamic.process.command_line": [r"C:\\Windows\\safe\.exe"]},
        "match": {"dynamic.process.file_name": [r"C:\Windows\safe2.exe"]},
    }

    with mock.patch("datetime.datetime", wraps=datetime.datetime) as dt:
        dt.utcnow.return_value = datetime.datetime(2024, 1, 1, 0, 0, 0)
        hatching_result_instance._process_processes(hatching_procs=hatching_procs)

    ontres_procs = hatching_result_instance.ontres.get_processes()

    expected_procs_as_primitivces = [
        {
            "objectid": {
                "tag": "?win\\malware.exe",
                "ontology_id": "process_2yB3VFLUxJI3i3E4aEtSND",
                "service_name": "HATCHING",
                "treeid": None,
                "processtree": None,
                "time_observed": "2024-01-01 00:00:01.156000",
            },
            "image": "C:\\Windows\\malware.exe",
            "start_time": "2024-01-01 00:00:01.156000",
            "pobjectid": None,
            "pimage": None,
            "pcommand_line": None,
            "ppid": 676,
            "pid": 2380,
            "command_line": "C:\\Windows\\malware.exe",
            "end_time": "2024-01-01 00:00:03.563000",
            "integrity_level": None,
            "image_hash": None,
            "original_file_name": None,
            "loaded_modules": None,
            "services_involved": None
        },
        {
            "objectid": {
                "tag": "/tmp/mal2",
                "ontology_id": "process_JcvZZPp2rdNOmesFS1OTE",
                "service_name": "HATCHING",
                "treeid": None,
                "processtree": None,
                "time_observed": "2024-01-01 00:00:03.300000",
            },
            "image": "/tmp/mal2",
            "start_time": "2024-01-01 00:00:03.300000",
            "pobjectid": None,
            "pimage": None,
            "pcommand_line": None,
            "ppid": 576,
            "pid": 587,
            "command_line": "/tmp/mal2",
            "end_time": "9999-12-31 23:59:59.999999",
            "integrity_level": None,
            "image_hash": None,
            "original_file_name": None,
            "loaded_modules": None,
            "services_involved": None
        },
    ]

    assert len(ontres_procs) == 2

    ontres_procs_as_primitives = [proc.as_primitives() for proc in ontres_procs]
    for procd in ontres_procs_as_primitives:
        # get rid of random session attr and guid
        procd.get("objectid").pop("session")
        procd.get("objectid").pop("guid")
        if procd.get("pobjectid"):
            procd.get("pobjectid").pop("session")
            procd.get("pobjectid").pop("guid")

        # log.warning(procd)
        assert procd in expected_procs_as_primitivces


def test_no_procs(
    hatching_result_instance: hatching_result_instance,
):
    """Validate the ontres has no procs."""

    # this will create a sandbox instance on ontres.sandboxes[] which is expected by _build_process_section()
    hatching_result_instance._update_ontres_for_dynamic_result_info_section(
        **ontres_dyn_kwargs
    )

    # Abbreviated example data created from a dynamic analysis triage report: .processes key
    hatching_procs = []

    hatching_result_instance._process_processes(hatching_procs=hatching_procs)

    ontres_procs = hatching_result_instance.ontres.get_processes()

    assert len(ontres_procs) == 0

import pytest
import json
import logging as log

from assemblyline_v4_service.common.result import BODY_FORMAT
from .utils import hatching_result_instance, find_result_section

ontres_dyn_kwargs = {
    "task_name": "test-profile-1",
    "start_time": "2023-09-19T18:52:26Z",
    "end_time": "2023-09-19T18:54:46Z",
    "platform": "windows10-2004_x64",
    "version": "0.3.0",
}


def test_build_process_section(
    hatching_result_instance: hatching_result_instance,
):
    """
    Validate the process section is present when all data is present.
    """
    # this will create a sandbox instance on ontres.sandboxes[] which is expected by _build_process_section()
    hatching_result_instance._update_ontres_for_dynamic_result_info_section(
        **ontres_dyn_kwargs
    )

    # Abbreviated example data created from a dynamic analysis triage report: .processes key
    hatching_procs = [
        {
            "procid": 79,
            "procid_parent": 54,
            "pid": 1244,
            "ppid": 3152,
            "cmd": "regsvr32 /s C:\\Users\\Admin\\AppData\\Local\\Temp\\test11.dll",
            "image": "C:\\Windows\\system32\\regsvr32.exe",
            "orig": True,
            "started": 407,
        },
        {
            "procid": 80,
            "procid_parent": 79,
            "pid": 5012,
            "ppid": 1244,
            "cmd": " /s C:\\Users\\Admin\\AppData\\Local\\Temp\\test11.dll",
            "image": "C:\\Windows\\SysWOW64\\regsvr32.exe",
            "orig": True,
            "started": 532,
        },
    ]

    section = hatching_result_instance._build_processes_section(
        hatching_procs=hatching_procs
    )

    # Validate main section
    assert section is not None

    assert section.title_text == "Spawned Process Tree"
    assert section.body_format == BODY_FORMAT.PROCESS_TREE
    # log.warning(section.section_body.__dict__["_data"])
    assert section.section_body.__dict__["_data"] == [
        {
            "process_pid": 1244,
            "process_name": "C:\\Windows\\system32\\regsvr32.exe",
            "command_line": "regsvr32 /s C:\\Users\\Admin\\AppData\\Local\\Temp\\test11.dll",
            "signatures": {},
            "children": [
                {
                    "process_pid": 5012,
                    "process_name": "C:\\Windows\\SysWOW64\\regsvr32.exe",
                    "command_line": " /s C:\\Users\\Admin\\AppData\\Local\\Temp\\test11.dll",
                    "signatures": {},
                    "children": [],
                    "network_count": 0,
                    "file_count": 0,
                    "registry_count": 0,
                    "safelisted": False,
                }
            ],
            "network_count": 0,
            "file_count": 0,
            "registry_count": 0,
            "safelisted": False,
        }
    ]
    assert section.heuristic._heur_id is 56
    # log.warning(section.tags)
    assert section.tags == {
        "dynamic.processtree_id": [
            "?sys32\\regsvr32.exe",
            "?sys32\\regsvr32.exe|?sys32\\regsvr32.exe",
        ],
        "dynamic.process.command_line": [
            "regsvr32 /s C:\\Users\\Admin\\AppData\\Local\\Temp\\test11.dll",
            " /s C:\\Users\\Admin\\AppData\\Local\\Temp\\test11.dll",
        ],
    }

    assert len(section.subsections) == 0


def test_build_process_section_filtered(
    hatching_result_instance: hatching_result_instance,
):
    """Validate the results are filtered when found in the safelist."""

    # this will create a sandbox instance on ontres.sandboxes[] which is expected by _build_process_section()
    hatching_result_instance._update_ontres_for_dynamic_result_info_section(
        **ontres_dyn_kwargs
    )

    # Abbreviated example data created from a dynamic analysis triage report: .processes key
    hatching_procs = [
        {
            "procid": 27,
            "procid_parent": 5,
            "pid": 2292,
            "ppid": 1276,
            "cmd": "C:\\Users\\Admin\\AppData\\Local\\Temp\\test22.exe",
            "image": "C:\\Users\\Admin\\AppData\\Local\\Temp\\test22.exe",
            "orig": False,
            "started": 343,
        },
        {
            "procid": 29,
            "procid_parent": 27,
            "pid": 948,
            "ppid": 2292,
            "cmd": "C:\\Windows\\SysWOW64\\WerFault.exe",
            "image": "C:\\Windows\\SysWOW64\\WerFault.exe",
            "orig": False,
            "started": 468,
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
        "regex": {
            "dynamic.process.command_line": [r"C:\\Windows\\SysWOW64\\WerFault\.exe"]
        },
        "match": {
            "dynamic.process.file_name": [r"C:\Windows\SysWOW64\WerFault2.exe"]
        },
    }

    section = hatching_result_instance._build_processes_section(
        hatching_procs=hatching_procs
    )

    # Validate main section
    assert section is not None

    assert section.title_text == "Spawned Process Tree"
    assert section.body_format == BODY_FORMAT.PROCESS_TREE
    # log.warning(section.section_body.__dict__["_data"])
    assert section.section_body.__dict__["_data"] == [
        {
            "process_pid": 2292,
            "process_name": "C:\\Users\\Admin\\AppData\\Local\\Temp\\test22.exe",
            "command_line": "C:\\Users\\Admin\\AppData\\Local\\Temp\\test22.exe",
            "signatures": {},
            "children": [],
            "network_count": 0,
            "file_count": 0,
            "registry_count": 0,
            "safelisted": False,
        }
    ]

    assert section.heuristic is None
    # log.warning(section.tags)
    assert section.tags == {
        "dynamic.processtree_id": ["?usrtmp\\test22.exe"],
        "dynamic.process.command_line": [
            "C:\\Users\\Admin\\AppData\\Local\\Temp\\test22.exe"
        ],
    }

    assert len(section.subsections) == 0


def test_returns_none(
    hatching_result_instance: hatching_result_instance,
):
    """Validate the Result is returned as None when no data presented."""

    # this will create a sandbox instance on ontres.sandboxes[] which is expected by _build_process_section()
    hatching_result_instance._update_ontres_for_dynamic_result_info_section(
        **ontres_dyn_kwargs
    )

    # Abbreviated example data created from a dynamic analysis triage report: .processes key
    hatching_procs = []
    section = hatching_result_instance._build_processes_section(
        hatching_procs=hatching_procs
    )
    assert section is None

    hatching_procs = []
    section = hatching_result_instance._build_processes_section(
        hatching_procs=hatching_procs
    )
    assert section is None

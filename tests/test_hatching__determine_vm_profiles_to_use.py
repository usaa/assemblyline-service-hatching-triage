import pytest
import json
import logging as log
import re

from unittest import mock
from unittest.mock import patch
from unittest.mock import MagicMock, PropertyMock

from .utils import hatching_service_instance

from hatching.hatching import VMPlatform


def test_determine_vm_profiles_to_use_with_autodetect(hatching_service_instance):
    """Validate the proper vm-profile is selected when the 'auto-detect-platform' param is used.

    A macos mach-o is used for the file_type which should return a macos-profile as defined in the default
    service_manifest.yml
    """

    service_request_mock = MagicMock()
    file_type_mock = PropertyMock(return_value="executable/mach-o")
    type(service_request_mock).file_type = file_type_mock
    hatching_service_instance.service_request = service_request_mock

    vm_profiles = hatching_service_instance._determine_vm_profiles_to_use(
        "auto-detect-platform"
    )
    # log.warning(vm_profile)
    assert vm_profiles == ["macos-profile"]


def test_determine_vm_profiles_to_use_with_autodetect_and_no_configured_platform(
    hatching_service_instance,
):
    """Validate the default vm-profile is selected when the 'auto-detect-platform' param is used and the platform
    detected is not configured by the admin in the service_manifest.

    in this example, the android platform is removed from the config, so the default should be used.
    """

    service_request_mock = MagicMock()
    file_type_mock = PropertyMock(return_value="android/apk")
    type(service_request_mock).file_type = file_type_mock
    hatching_service_instance.service_request = service_request_mock

    # Override the default service_manifest to remove android from being configured.
    vm_profile_autodetect_map_override = {
        "windows": ["win-profile"],
        "macos": ["macos-profile"],
        "linux": ["linux-profile"],
        # "android": ["android-profile"],
        "default": ["win-profile"],
    }
    hatching_service_instance.config[
        "vm_profile_autodetect_map"
    ] = vm_profile_autodetect_map_override
    log.warning(hatching_service_instance.config)

    vm_profiles = hatching_service_instance._determine_vm_profiles_to_use(
        "auto-detect-platform"
    )
    # log.warning(vm_profile)
    assert vm_profiles == ["win-profile"]


def test_determine_vm_profiles_to_use_when_not_autodetect(hatching_service_instance):
    """Validate that when a valid profile is used other than 'auto-detect-platform, that it is returned."""
    vm_profiles = hatching_service_instance._determine_vm_profiles_to_use("win-profile")
    # log.warning(vm_profile)
    assert vm_profiles == ["win-profile"]


def test_raises_exception(hatching_service_instance):
    """Validate that if a profile is used OTHER than what is defined by the admin in the submission_params that an
    exception is raised.
    """
    with pytest.raises(
        ValueError, match=re.escape("Invalid value used in the submission parameter: vm_profile.")
    ):
        vm_profiles = hatching_service_instance._determine_vm_profiles_to_use(
            "other-invalid"
        )

    with pytest.raises(
        ValueError, match=re.escape("Invalid value used in the submission parameter: vm_profile.")
    ):
        vm_profiles = hatching_service_instance._determine_vm_profiles_to_use("")

    with pytest.raises(
        ValueError, match=re.escape("Invalid value used in the submission parameter: vm_profile.")
    ):
        vm_profiles = hatching_service_instance._determine_vm_profiles_to_use(None)

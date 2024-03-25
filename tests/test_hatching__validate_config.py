import pytest
import json
import logging as log
import re

from unittest import mock
from unittest.mock import patch
from unittest.mock import MagicMock, PropertyMock

from hatching.hatching import InvalidConfigurationException

from .utils import hatching_service_instance


def test_validate_config(hatching_service_instance):
    """Validate the _validate_config method validates properly when the default service_manifest is used."""

    log.warning(hatching_service_instance.config.get("vm_profile_autodetect_map"))
    assert hatching_service_instance._validate_config() is True


def test_raises_exception(hatching_service_instance):
    """Validate the following scenarios raise an InvalidConfigurationException."""
    #
    # Scenario 1a - Required keys not present
    vm_profile_autodetect_map_override = {
        "windows": ["win-profile"],
    }
    hatching_service_instance.config[
        "vm_profile_autodetect_map"
    ] = vm_profile_autodetect_map_override
    with pytest.raises(
        InvalidConfigurationException,
        match=re.escape("The service_manifest config key is not configured properly. The vm_profile_autodetect_map key must have the following required keys: ['default']"),
    ):
        vm_profiles = hatching_service_instance._validate_config()

    #
    # Scenario 1b - Required keys not present
    vm_profile_autodetect_map_override = {}
    hatching_service_instance.config[
        "vm_profile_autodetect_map"
    ] = vm_profile_autodetect_map_override
    with pytest.raises(
        InvalidConfigurationException,
        match=re.escape("The service_manifest config key is not configured properly. The vm_profile_autodetect_map key must have the following required keys: ['default']"),
    ):
        vm_profiles = hatching_service_instance._validate_config()

    #
    # Scenario 2 - Other keys not defined as required or optional are present
    vm_profile_autodetect_map_override = {
        "other": ["win-profile"],
        "default": ["win-profile"],
    }
    hatching_service_instance.config[
        "vm_profile_autodetect_map"
    ] = vm_profile_autodetect_map_override
    with pytest.raises(
        InvalidConfigurationException,
        match=re.escape("The service_manifest config key is not configured properly. The vm_profile_autodetect_map key must has unexpected keys present. It can only have the required keys: ['default'] and optional keys: ['windows', 'linux', 'macos', 'android']"),
    ):
        vm_profiles = hatching_service_instance._validate_config()

    #
    # Scenario 3a - Values not properly defined for keys
    vm_profile_autodetect_map_override = {
        "windows": "test",
        "macos": ["macos-profile"],
        "linux": ["linux-profile"],
        "android": ["android-profile"],
        "default": ["win-profile"],
    }
    hatching_service_instance.config[
        "vm_profile_autodetect_map"
    ] = vm_profile_autodetect_map_override
    with pytest.raises(
        InvalidConfigurationException,
        match=re.escape("The service_manifest config.vm_profile_autodetect_map key has unexpected values. Each key must have a list type with at least one value in the list."),
    ):
        vm_profiles = hatching_service_instance._validate_config()

    #
    # Scenario 3b - Values not properly defined for keys
    vm_profile_autodetect_map_override = {
        "windows": ["win-profile"],
        "macos": ["macos-profile"],
        "linux": ["linux-profile"],
        "android": ["android-profile"],
        "default": "invalid-val",
    }
    hatching_service_instance.config[
        "vm_profile_autodetect_map"
    ] = vm_profile_autodetect_map_override
    with pytest.raises(
        InvalidConfigurationException,
        match=re.escape("The service_manifest config.vm_profile_autodetect_map key has unexpected values. Each key must have a list type with at least one value in the list."),
    ):
        vm_profiles = hatching_service_instance._validate_config()

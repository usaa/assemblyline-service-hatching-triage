import pytest
import json
import logging as log

from unittest import mock
from unittest.mock import patch
from unittest.mock import MagicMock, PropertyMock

from .utils import hatching_service_instance

from hatching.hatching import VMPlatform


def test_auto_detect_vm_platform(hatching_service_instance):
    """Validate the proper vm-profile is selected based on the file type."""

    # Android
    file_type = "android/dex"
    platform = hatching_service_instance._auto_detect_vm_platform(file_type)
    assert platform == VMPlatform.ANDROID.value

    # Linux
    file_type = "executable/linux/coff64"
    platform = hatching_service_instance._auto_detect_vm_platform(file_type)
    assert platform == VMPlatform.LINUX.value

    file_type = "executable/linux/elf64"
    platform = hatching_service_instance._auto_detect_vm_platform(file_type)
    assert platform == VMPlatform.LINUX.value

    # Macos
    file_type = "executable/mach-o"
    platform = hatching_service_instance._auto_detect_vm_platform(file_type)
    assert platform == VMPlatform.MACOS.value

    # Windows
    file_type = "executable/windows/dll64"
    platform = hatching_service_instance._auto_detect_vm_platform(file_type)
    assert platform == VMPlatform.WINDOWS.value

    file_type = "executable/windows/pe"
    platform = hatching_service_instance._auto_detect_vm_platform(file_type)
    assert platform == VMPlatform.WINDOWS.value

    # Default platform
    file_type = "document/pdf"
    platform = hatching_service_instance._auto_detect_vm_platform(file_type)
    assert platform == VMPlatform.DEFAULT.value

    file_type = "document/office/rtf"
    platform = hatching_service_instance._auto_detect_vm_platform(file_type)
    assert platform == VMPlatform.DEFAULT.value

    file_type = ""
    platform = hatching_service_instance._auto_detect_vm_platform(file_type)
    assert platform == VMPlatform.DEFAULT.value

    file_type = None
    platform = hatching_service_instance._auto_detect_vm_platform(file_type)
    assert platform == VMPlatform.DEFAULT.value

import json
import pytest

from assemblyline_v4_service.common.result import BODY_FORMAT
from .utils import hatching_result_instance, HATCHING_ENDPOINT_URL


def test_build_link_section(hatching_result_instance: hatching_result_instance):
    """Validate link ResultSection created properly."""

    section = hatching_result_instance._build_link_section()

    assert section.title_text == "Link to Hatching Triage Analysis"
    assert section.body_format == BODY_FORMAT.URL

    body = section.body
    url = f"{HATCHING_ENDPOINT_URL}/230815-xxxyyyzzz1"
    assert json.loads(body) == {"name": url, "url": url}

    assert section.heuristic is None
    assert section.tags == {}
    assert len(section.subsections) == 0


def test_returns_none(hatching_result_instance: hatching_result_instance):
    """Validate link ResultSection not created when data is missing"""

    hatching_result_instance.web_url = None
    hatching_result_instance.sample_id = "test1"
    section = hatching_result_instance._build_link_section()
    assert section is None

    hatching_result_instance.web_url = "https://test.local/1"
    hatching_result_instance.sample_id = None
    section = hatching_result_instance._build_link_section()
    assert section is None

    hatching_result_instance.web_url = None
    hatching_result_instance.sample_id = None
    section = hatching_result_instance._build_link_section()
    assert section is None

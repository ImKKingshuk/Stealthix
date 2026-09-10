from __future__ import annotations

import pytest

from stealthix.templates import (
    TemplateResponse,
    TemplateValidationError,
    evaluate_template,
    load_stealthix_template,
    request_specs_for_template,
)


def test_template_loader_evaluates_matchers_and_extractors():
    template = load_stealthix_template(
        """
id: tech-detect
info:
  name: Demo detector
  severity: info
http:
  - method: GET
    path:
      - "{{BaseURL}}/version"
    matchers-condition: and
    matchers:
      - type: status
        status: [200]
      - type: word
        part: body
        words: ["Stealthix"]
      - type: regex
        part: header
        regex: ["Server: demo"]
    extractors:
      - type: regex
        name: version
        part: body
        regex: ["version=([0-9.]+)"]
        group: 1
"""
    )

    [spec] = request_specs_for_template(template, "https://example.test")
    result = evaluate_template(
        template,
        TemplateResponse(
            status_code=200,
            headers={"Server": "demo"},
            body="Welcome to Stealthix version=1.2.3",
        ),
    )

    assert spec.url == "https://example.test/version"
    assert result.matched is True
    assert [(item.name, item.value) for item in result.extracts] == [("version", "1.2.3")]


def test_template_loader_supports_json_documents():
    template = load_stealthix_template(
        {
            "id": "json-template",
            "http": [
                {
                    "method": "HEAD",
                    "path": "/health",
                    "matchers": [{"type": "status", "status": [204]}],
                }
            ],
        }
    )

    result = evaluate_template(template, {"status_code": 204, "headers": {}, "body": ""})

    assert template.id == "json-template"
    assert result.matched is True


def test_template_safe_defaults_reject_active_http_fields_and_unsafe_methods():
    with pytest.raises(TemplateValidationError, match="unsafe method POST"):
        load_stealthix_template(
            {
                "id": "post-template",
                "http": [
                    {
                        "method": "POST",
                        "path": "/login",
                        "matchers": [{"type": "status", "status": [200]}],
                    }
                ],
            }
        )

    with pytest.raises(TemplateValidationError, match="unsupported active HTTP fields"):
        load_stealthix_template(
            {
                "id": "raw-template",
                "http": [
                    {
                        "method": "GET",
                        "path": "/",
                        "raw": ["GET / HTTP/1.1"],
                        "matchers": [{"type": "status", "status": [200]}],
                    }
                ],
            }
        )


def test_template_validation_reports_schema_errors():
    with pytest.raises(TemplateValidationError, match="'matchers' is a required property"):
        load_stealthix_template(
            {
                "id": "invalid-template",
                "http": [{"method": "GET", "path": "/"}],
            }
        )

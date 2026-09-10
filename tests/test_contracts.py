from __future__ import annotations

import json

from agentflow.contracts import SCHEMA_ERROR_CAP, parse_json_output, validate_json_instance


def test_parse_json_output_accepts_whole_text_and_a_single_fence():
    assert parse_json_output('{"a": 1}') == ({"a": 1}, None)
    assert parse_json_output('```json\n{"a": 1}\n```') == ({"a": 1}, None)
    assert parse_json_output("```\n[1, 2]\n```") == ([1, 2], None)


def test_parse_json_output_reads_a_fence_after_prose():
    text = 'Here is the result you asked for:\n\n```json\n{"result": "EXHAUSTED", "leads": []}\n```'

    assert parse_json_output(text) == ({"result": "EXHAUSTED", "leads": []}, None)


def test_parse_json_output_reads_a_fence_followed_by_a_trailing_note():
    text = '```json\n{"count": 2}\n```\n\nLet me know if you need anything else.'

    assert parse_json_output(text) == ({"count": 2}, None)


def test_parse_json_output_prefers_the_last_fenced_block():
    text = 'Draft:\n```json\n{"draft": true}\n```\nFinal:\n```JSON\n{"draft": false}\n```'

    assert parse_json_output(text) == ({"draft": False}, None)


def test_parse_json_output_reads_a_raw_value_after_a_preamble_line():
    text = 'Final answer:\n{"nested": {"ok": true}, "items": [1, {"deep": [2]}]}'

    assert parse_json_output(text) == ({"nested": {"ok": True}, "items": [1, {"deep": [2]}]}, None)
    assert parse_json_output("Values: [1, 2, 3]  \n") == ([1, 2, 3], None)


def test_parse_json_output_keeps_fence_markers_inside_json_strings():
    report = {"findingId": "finding_abc", "markdown": "# T\n\n```bash\ncmd\n```\n"}
    fenced = "```json\n" + json.dumps(report) + "\n```"

    assert parse_json_output(fenced) == (report, None)
    assert parse_json_output("Here you go:\n\n" + fenced) == (report, None)
    assert parse_json_output(fenced + "\n\nDone.") == (report, None)
    lead = {"leads": [{"evidence": "see ```rust\nfn x()\n``` above", "claim": "c"}]}
    assert parse_json_output("```\n" + json.dumps(lead, indent=2) + "\n```") == (lead, None)


def test_parse_json_output_ignores_prose_with_bracketed_footnotes():
    assert parse_json_output("see [1]") == (None, "output is not valid JSON: Expecting value at line 1 column 1")
    assert parse_json_output("Sources: [1] and [2]")[0] is None
    assert parse_json_output("Result {\"a\": 1}")[0] is None
    assert parse_json_output("Result: {\"a\": 1}") == ({"a": 1}, None)
    assert parse_json_output("Result\n  [1, 2]") == ([1, 2], None)


def test_parse_json_output_rejects_json_that_does_not_reach_the_end():
    value, error = parse_json_output('{"a": 1} and then some prose.')

    assert value is None
    assert error == "output is not valid JSON: Extra data at line 1 column 10"


def test_parse_json_output_reports_garbage_and_empty_text():
    value, error = parse_json_output("this is not json at all")

    assert value is None
    assert error == "output is not valid JSON: Expecting value at line 1 column 1"
    assert parse_json_output("   \n") == (None, "output is empty")
    assert parse_json_output(None) == (None, "output is empty")


ITEMS_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "required": ["name", "items"],
    "properties": {
        "name": {"type": "string"},
        "items": {
            "type": "array",
            "items": {
                "type": "object",
                "required": ["id"],
                "properties": {"id": {"type": "integer"}},
            },
        },
    },
}


def test_validate_json_instance_returns_no_errors_for_a_valid_instance():
    assert validate_json_instance({"name": "x", "items": [{"id": 1}]}, ITEMS_SCHEMA) == []


def test_validate_json_instance_formats_sorted_json_pointers():
    instance = {"name": 3, "items": [{"id": "a"}, {}], "extra": 1}

    assert validate_json_instance(instance, ITEMS_SCHEMA) == [
        "/: Additional properties are not allowed ('extra' was unexpected)",
        "/items/0/id: 'a' is not of type 'integer'",
        "/items/1: 'id' is a required property",
        "/name: 3 is not of type 'string'",
    ]


def test_validate_json_instance_uses_root_pointer_and_escapes_segments():
    assert validate_json_instance("nope", {"type": "object"}) == ["/: 'nope' is not of type 'object'"]

    schema = {"type": "object", "properties": {"a/b": {"type": "integer"}, "c~d": {"type": "integer"}}}

    assert validate_json_instance({"a/b": "x", "c~d": "y"}, schema) == [
        "/a~1b: 'x' is not of type 'integer'",
        "/c~0d: 'y' is not of type 'integer'",
    ]


def test_validate_json_instance_caps_the_error_list():
    errors = validate_json_instance(["s"] * 30, {"type": "array", "items": {"type": "integer"}})

    assert len(errors) == SCHEMA_ERROR_CAP
    assert errors[0] == "/0: 's' is not of type 'integer'"

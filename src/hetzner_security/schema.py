"""Runtime JSON Schema validation with the standard library only.

Implements the subset of draft 2020-12 the project's schemas use: type, const, enum, required,
properties, additionalProperties, items, minItems, uniqueItems, minLength, pattern, minimum,
maximum, exclusiveMinimum, local `#/$defs/...` references, and references to sibling schema files.
`format` is ignored, as JSON Schema allows. The test suite checks agreement with `jsonschema`.
"""

from __future__ import annotations

import json
import re
from functools import cache
from pathlib import Path
from typing import Any

MAX_ERRORS = 20


def schema_dir() -> Path:
    packaged = Path(__file__).parent / "schemas"  # installed wheel
    return packaged if packaged.is_dir() else Path(__file__).resolve().parents[2] / "schemas"  # source checkout


@cache
def load_schema(name: str) -> dict[str, Any]:
    value: dict[str, Any] = json.loads((schema_dir() / name).read_text(encoding="utf-8"))
    return value


TYPES: dict[str, tuple[type, ...]] = {
    "object": (dict,), "array": (list,), "string": (str,), "boolean": (bool,), "null": (type(None),),
    "integer": (int,), "number": (int, float),
}


def _is_type(value: Any, name: str) -> bool:
    if name in {"integer", "number"} and isinstance(value, bool):
        return False
    if name == "integer" and isinstance(value, float):
        return value.is_integer()
    return isinstance(value, TYPES[name])


def _validate(value: Any, schema: dict[str, Any], root: dict[str, Any], path: str, errors: list[str]) -> None:
    if len(errors) >= MAX_ERRORS:
        return
    if "$ref" in schema:
        ref = str(schema["$ref"])
        if ref.startswith("#/$defs/"):
            _validate(value, root["$defs"][ref.removeprefix("#/$defs/")], root, path, errors)
        else:
            target = load_schema(ref)
            _validate(value, target, target, path, errors)
        return
    expected = schema.get("type")
    if expected is not None:
        names = expected if isinstance(expected, list) else [expected]
        if not any(_is_type(value, name) for name in names):
            errors.append(f"{path or '$'}: expected {' or '.join(names)}, got {type(value).__name__}")
            return
    if "const" in schema and value != schema["const"]:
        errors.append(f"{path or '$'}: must be {schema['const']!r}")
    if "enum" in schema and value not in schema["enum"]:
        errors.append(f"{path or '$'}: {value!r} is not one of {schema['enum']}")
    if isinstance(value, dict):
        for key in schema.get("required", []):
            if key not in value:
                errors.append(f"{path or '$'}: missing required field {key!r}")
        properties = schema.get("properties", {})
        extra = schema.get("additionalProperties", True)
        for key, item in value.items():
            if key in properties:
                _validate(item, properties[key], root, f"{path}.{key}", errors)
            elif extra is False:
                errors.append(f"{path or '$'}: unknown field {key!r}")
            elif isinstance(extra, dict):
                _validate(item, extra, root, f"{path}.{key}", errors)
    if isinstance(value, list):
        if len(value) < schema.get("minItems", 0):
            errors.append(f"{path or '$'}: needs at least {schema['minItems']} item(s)")
        if schema.get("uniqueItems") and len({json.dumps(item, sort_keys=True) for item in value}) != len(value):
            errors.append(f"{path or '$'}: items must be unique")
        if isinstance(schema.get("items"), dict):
            for index, item in enumerate(value):
                _validate(item, schema["items"], root, f"{path}[{index}]", errors)
    if isinstance(value, str):
        if len(value) < schema.get("minLength", 0):
            errors.append(f"{path or '$'}: shorter than {schema['minLength']}")
        if "pattern" in schema and not re.search(schema["pattern"], value):
            errors.append(f"{path or '$'}: does not match {schema['pattern']!r}")
    if _is_type(value, "number"):
        if "minimum" in schema and value < schema["minimum"]:
            errors.append(f"{path or '$'}: below minimum {schema['minimum']}")
        if "maximum" in schema and value > schema["maximum"]:
            errors.append(f"{path or '$'}: above maximum {schema['maximum']}")
        if "exclusiveMinimum" in schema and value <= schema["exclusiveMinimum"]:
            errors.append(f"{path or '$'}: must be greater than {schema['exclusiveMinimum']}")


def validation_errors(value: Any, schema_name: str) -> list[str]:
    schema = load_schema(schema_name)
    errors: list[str] = []
    _validate(value, schema, schema, "", errors)
    return errors


def validate(value: Any, schema_name: str, what: str) -> None:
    """Raise ValueError listing the first problems when ``value`` does not match the schema."""
    errors = validation_errors(value, schema_name)
    if errors:
        raise ValueError(f"{what} does not match {schema_name}: " + "; ".join(errors[:5]) + (" …" if len(errors) > 5 else ""))

import json


def is_valid_prompt(prompt):
    """
    Validate the basic structure of an incoming prompt.
    """

    if not isinstance(prompt, str):
        return False

    prompt = prompt.strip()

    if not prompt:
        return False

    return True


def sanitize_prompt(prompt):
    """
    Perform basic input normalization.

    This is not intended to be the security scanner.
    The actual security analysis happens in the rule engine
    and Gemini semantic layer.
    """

    if not isinstance(prompt, str):
        return ""

    return prompt.strip()


def safe_json_dumps(value):
    """
    Convert Python data into JSON text for database storage.
    """

    try:
        return json.dumps(
            value,
            ensure_ascii=False
        )
    except (TypeError, ValueError):
        return "{}"


def safe_int(value, default=0):
    """
    Safely convert a value to integer.
    """

    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def safe_float(value, default=0):
    """
    Safely convert a value to float.
    """

    try:
        return float(value)
    except (TypeError, ValueError):
        return default
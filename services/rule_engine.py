import re


# -------------------------------------------------------------------
# Prompt Shield Rule Library
# -------------------------------------------------------------------
#
# Each rule contains:
#
# pattern      -> regular expression used to identify the behaviour
# threat_type  -> category of the potential attack
# severity     -> severity contribution from 0 to 100
# description  -> human readable explanation
#
# The patterns are intentionally contextual rather than simply
# blocking words such as "ignore" because harmless prompts can
# legitimately contain those words.
# -------------------------------------------------------------------

RULES = [
    {
        "pattern": (
            r"\b(?:create|build|make|design|deploy|write)\w*\s+"
            r"(?:a\s+)?(?:fake|fraudulent|spoofed|lookalike)\s+"
            r"(?:banking\s+|bank\s+|payment\s+)?"
            r"(?:login|log-?in|sign-?in)\s+"
            r"(?:page|website|site|form)\b.*"
            r"\b(?:trick|deceive|lure|phish)\w*\s+"
            r"(?:users|people|victims)\s+into\s+"
            r"(?:entering|sharing|submitting|providing)\b.*"
            r"\b(?:usernames?|passwords?|credentials?)\b"
        ),
        "threat_type": "Credential Phishing",
        "severity": 98,
        "description": (
            "The prompt requests creating an impersonating login page "
            "to trick people into disclosing credentials."
        )
    },
    {
        "pattern": (
            r"\b(?:steal|harvest|capture|collect|exfiltrate)\w*\s+"
            r"(?:users'?\s+)?(?:usernames?|passwords?|login credentials)\b"
        ),
        "threat_type": "Credential Phishing",
        "severity": 95,
        "description": (
            "The prompt requests stealing or collecting login credentials."
        )
    },
    {
        "pattern": r"ignore\s+(all\s+)?previous\s+instructions",
        "threat_type": "Prompt Injection",
        "severity": 90,
        "description": (
            "The prompt attempts to override instructions that "
            "were previously provided to the model."
        )
    },
    {
        "pattern": r"ignore\s+(the\s+)?system\s+prompt",
        "threat_type": "Prompt Injection",
        "severity": 95,
        "description": (
            "The prompt explicitly attempts to override or bypass "
            "the model's system instructions."
        )
    },
    {
        "pattern": r"disregard\s+(all\s+)?previous\s+instructions",
        "threat_type": "Prompt Injection",
        "severity": 90,
        "description": (
            "The prompt attempts to replace previously established "
            "instructions."
        )
    },
    {
        "pattern": r"forget\s+(all\s+)?previous\s+instructions",
        "threat_type": "Prompt Injection",
        "severity": 88,
        "description": (
            "The prompt attempts to make the model discard its "
            "existing instructions."
        )
    },
    {
        "pattern": r"reveal\s+(your\s+)?system\s+prompt",
        "threat_type": "Data Exfiltration",
        "severity": 95,
        "description": (
            "The prompt requests disclosure of hidden system "
            "instructions."
        )
    },
    {
        "pattern": r"show\s+(me\s+)?your\s+system\s+prompt",
        "threat_type": "Data Exfiltration",
        "severity": 95,
        "description": (
            "The prompt requests information that may belong to "
            "the protected system configuration."
        )
    },
    {
        "pattern": r"print\s+(your\s+)?system\s+instructions",
        "threat_type": "Data Exfiltration",
        "severity": 95,
        "description": (
            "The prompt attempts to extract hidden system "
            "instructions."
        )
    },
    {
        "pattern": r"reveal\s+(your\s+)?hidden\s+instructions",
        "threat_type": "Data Exfiltration",
        "severity": 95,
        "description": (
            "The prompt requests disclosure of hidden instructions."
        )
    },
    {
        "pattern": r"what\s+are\s+your\s+hidden\s+instructions",
        "threat_type": "Data Exfiltration",
        "severity": 90,
        "description": (
            "The prompt attempts to discover protected model "
            "instructions."
        )
    },
    {
        "pattern": r"pretend\s+you\s+are\s+(an?\s+)?(unrestricted|uncensored|unfiltered)",
        "threat_type": "Jailbreak Attempt",
        "severity": 90,
        "description": (
            "The prompt uses an unrestricted role to attempt to "
            "bypass model safety behaviour."
        )
    },
    {
        "pattern": r"pretend\s+you\s+have\s+no\s+(rules|restrictions|limitations)",
        "threat_type": "Jailbreak Attempt",
        "severity": 92,
        "description": (
            "The prompt explicitly asks the model to operate "
            "without its normal restrictions."
        )
    },
    {
        "pattern": r"act\s+as\s+(an?\s+)?(unrestricted|uncensored|evil)\s+(ai|assistant|model)",
        "threat_type": "Jailbreak Attempt",
        "severity": 92,
        "description": (
            "The prompt attempts to create a role that bypasses "
            "normal model restrictions."
        )
    },
    {
        "pattern": r"bypass\s+(your\s+)?(safety|security)\s+(rules|filters|restrictions)",
        "threat_type": "Jailbreak Attempt",
        "severity": 95,
        "description": (
            "The prompt explicitly requests bypassing model "
            "safety controls."
        )
    },
    {
        "pattern": r"disable\s+(your\s+)?(safety|security)\s+(filter|filters|rules)",
        "threat_type": "Jailbreak Attempt",
        "severity": 95,
        "description": (
            "The prompt requests disabling safety mechanisms."
        )
    },
    {
        "pattern": r"developer\s+message\s*:",
        "threat_type": "Prompt Injection",
        "severity": 75,
        "description": (
            "The prompt attempts to impersonate a higher priority "
            "instruction source."
        )
    },
    {
        "pattern": r"system\s+message\s*:",
        "threat_type": "Prompt Injection",
        "severity": 75,
        "description": (
            "The prompt attempts to imitate a system-level message."
        )
    },
    {
        "pattern": r"new\s+system\s+instruction",
        "threat_type": "Prompt Injection",
        "severity": 85,
        "description": (
            "The prompt attempts to introduce a new system-level "
            "instruction."
        )
    },
    {
        "pattern": r"do\s+not\s+tell\s+the\s+user\s+that",
        "threat_type": "Prompt Injection",
        "severity": 70,
        "description": (
            "The prompt attempts to control what information is "
            "revealed to the user."
        )
    },
    {
        "pattern": r"keep\s+this\s+(secret|hidden)\s+from\s+the\s+user",
        "threat_type": "Prompt Injection",
        "severity": 75,
        "description": (
            "The prompt attempts to establish hidden behaviour "
            "that should not be disclosed."
        )
    },
    {
        "pattern": r"reveal\s+(the\s+)?(api|secret)\s+key",
        "threat_type": "Data Exfiltration",
        "severity": 98,
        "description": (
            "The prompt requests a potentially sensitive API or "
            "secret key."
        )
    },
    {
        "pattern": r"show\s+(me\s+)?(the\s+)?password",
        "threat_type": "Data Exfiltration",
        "severity": 90,
        "description": (
            "The prompt requests potentially confidential "
            "authentication information."
        )
    },
    {
        "pattern": r"give\s+me\s+(the\s+)?credentials",
        "threat_type": "Data Exfiltration",
        "severity": 90,
        "description": (
            "The prompt requests potentially sensitive credentials."
        )
    },
    {
        "pattern": r"decode\s+(this|the)\s+(hidden|secret|encoded)\s+(instruction|prompt)",
        "threat_type": "Prompt Injection",
        "severity": 70,
        "description": (
            "The prompt may be attempting to hide instructions "
            "through encoding or obfuscation."
        )
    },
    {
        "pattern": r"base64.*instruction",
        "threat_type": "Obfuscation",
        "severity": 65,
        "description": (
            "The prompt references encoded instructions, which "
            "can be used to hide malicious content."
        )
    }
]


def normalize_prompt(prompt):
    """
    Normalize a prompt before applying detection rules.

    We keep the original prompt untouched elsewhere.
    """

    if not isinstance(prompt, str):
        return ""

    normalized = prompt.strip().lower()

    normalized = re.sub(
        r"\s+",
        " ",
        normalized
    )

    return normalized


def scan_with_rules(prompt):
    """
    Run the rule based security scanner.

    Returns:

    {
        "matched": True/False,
        "rule_score": 0-100,
        "threat_type": "...",
        "findings": [...]
    }
    """

    normalized_prompt = normalize_prompt(prompt)

    findings = []

    for rule in RULES:

        try:
            match = re.search(
                rule["pattern"],
                normalized_prompt,
                flags=re.IGNORECASE
            )
        except re.error:
            continue

        if match:
            findings.append(
                {
                    "threat_type": rule["threat_type"],
                    "severity": rule["severity"],
                    "description": rule["description"],
                    "matched_text": match.group(0)
                }
            )

    if not findings:
        return {
            "matched": False,
            "rule_score": 0,
            "threat_type": "Benign",
            "findings": []
        }

    highest_severity = max(
        finding["severity"]
        for finding in findings
    )

    highest_severity_finding = max(
        findings,
        key=lambda finding: finding["severity"]
    )

    return {
        "matched": True,
        "rule_score": min(
            round(highest_severity, 2),
            100
        ),
        "threat_type": highest_severity_finding["threat_type"],
        "findings": findings
    }


def get_rule_summary(rule_result):
    """
    Convert rule findings into a concise human readable summary.
    """

    findings = rule_result.get("findings", [])

    if not findings:
        return "No high confidence rule based attack pattern was detected."

    descriptions = []

    for finding in findings:
        descriptions.append(
            finding["description"]
        )

    return " ".join(descriptions)
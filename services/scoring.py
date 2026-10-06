THREAT_WEIGHTS = {
    "Benign": 0.0,

    "Credential Phishing": 1.0,

    "Prompt Injection": 1.0,

    "Jailbreak Attempt": 1.0,

    "Data Exfiltration": 1.0,

    "PII Exposure Risk": 0.85,

    "Obfuscation": 0.75,

    "Other": 0.70
}


def clamp(value, minimum=0, maximum=100):
    """
    Keep a numerical value inside a defined range.
    """

    return max(
        minimum,
        min(value, maximum)
    )


def get_threat_weight(threat_type):
    """
    Return the configured weight for a threat type.
    """

    return THREAT_WEIGHTS.get(
        threat_type,
        THREAT_WEIGHTS["Other"]
    )


def calculate_security_score(
    rule_score,
    llm_confidence,
    threat_type,
    llm_threat_weight=None
):
    """
    Use the strongest independent signal so one detector cannot
    average a high-confidence finding down to a low risk score.
    """

    rule_score = clamp(
        float(rule_score)
    )

    llm_confidence = clamp(
        float(llm_confidence),
        0,
        1
    )

    if llm_threat_weight is None:
        threat_weight = get_threat_weight(
            threat_type
        )
    else:
        threat_weight = clamp(
            float(llm_threat_weight),
            0,
            1
        )

    rule_component = rule_score
    llm_component = llm_confidence * threat_weight * 100
    final_score = max(rule_component, llm_component)

    final_score = clamp(
        round(final_score, 2)
    )

    return {
        "score": final_score,
        "rule_component": round(
            rule_component,
            2
        ),
        "llm_component": round(
            llm_component,
            2
        ),
        "rule_score": round(
            rule_score,
            2
        ),
        "llm_confidence": round(
            llm_confidence,
            4
        ),
        "threat_weight": round(
            threat_weight,
            4
        )
    }


def get_risk_category(score):
    """
    Convert a 0-100 threat score into a risk category.
    """

    score = float(score)

    if score == 0:
        return "No Known Threat Detected"

    if score < 40:
        return "Low Risk"

    if score < 60:
        return "Medium Risk"

    if score < 80:
        return "High Risk"

    return "Critical"


def build_explanation(
    rule_result,
    llm_result,
    scoring_result
):
    """
    Build a plain language explanation using the results
    from both the rule engine and Gemini.
    """

    score = scoring_result["score"]

    risk_category = get_risk_category(
        score
    )

    threat_type = llm_result.get(
        "threat_type",
        rule_result.get(
            "threat_type",
            "Benign"
        )
    )

    llm_explanation = llm_result.get(
        "explanation",
        ""
    ).strip()

    rule_findings = rule_result.get(
        "findings",
        []
    )

    parts = []

    if risk_category == "No Known Threat Detected":
        parts.append(
            "No known attack indicators were detected. Automated "
            "analysis cannot prove that a prompt is safe."
        )

    elif risk_category == "Low Risk":
        parts.append(
            "The prompt contains a small number of signals that "
            "may require attention, but the overall security risk "
            "is relatively low."
        )

    elif risk_category == "Medium Risk":
        parts.append(
            "The prompt contains suspicious behaviour that could "
            "interfere with the intended behaviour of an AI system."
        )

    elif risk_category == "High Risk":
        parts.append(
            "The prompt contains strong indicators of malicious "
            "or unsafe manipulation of an AI system."
        )

    else:
        parts.append(
            "The prompt contains highly significant indicators of "
            "an AI security attack and should not be forwarded "
            "without review."
        )

    if threat_type and threat_type != "Benign":
        parts.append(
            f"Detected threat type: {threat_type}."
        )

    if rule_findings:
        parts.append(
            f"The rule based security layer identified "
            f"{len(rule_findings)} matching attack pattern(s)."
        )

    if llm_explanation:
        parts.append(
            f"Semantic analysis: {llm_explanation}"
        )

    return " ".join(parts)


def create_score_response(
    rule_result,
    llm_result
):
    """
    Combine rule detection and LLM detection into the final
    structured security result.
    """

    llm_threat_type = llm_result.get(
        "threat_type",
        "Benign"
    )

    rule_threat_type = rule_result.get(
        "threat_type",
        "Benign"
    )

    rule_score = rule_result.get("rule_score", 0)
    llm_signal = (
        float(llm_result.get("confidence", 0) or 0) *
        float(llm_result.get("threat_weight", 0) or 0) *
        100
    )

    if rule_score >= llm_signal and rule_result.get("matched"):
        final_threat_type = rule_threat_type
    elif llm_threat_type != "Benign":
        final_threat_type = llm_threat_type
    else:
        final_threat_type = rule_threat_type

    if not llm_result.get("available", True) and not rule_result.get("matched"):
        return {
            "score": None,
            "rule_component": 0,
            "llm_component": 0,
            "rule_score": 0,
            "llm_confidence": 0,
            "threat_weight": 0,
            "risk_category": "Needs Review",
            "threat_type": "Unclassified",
            "assessment_status": "unverified",
            "explanation": (
                "A reliable assessment could not be completed because "
                "semantic analysis is unavailable and no known rule "
                "matched. Treat this prompt as unverified, not safe."
            )
        }

    scoring_result = calculate_security_score(
        rule_score=rule_result.get(
            "rule_score",
            0
        ),
        llm_confidence=llm_result.get(
            "confidence",
            0
        ),
        threat_type=final_threat_type,
        llm_threat_weight=llm_result.get(
            "threat_weight"
        )
    )

    risk_category = get_risk_category(
        scoring_result["score"]
    )

    explanation = build_explanation(
        rule_result,
        llm_result,
        scoring_result
    )

    return {
        **scoring_result,
        "risk_category": risk_category,
        "threat_type": final_threat_type,
        "assessment_status": "complete" if llm_result.get("available", True) else "rule_only",
        "explanation": explanation
    }
SEVERITY_POINTS = {
    "Critical": 10,
    "High": 7,
    "Medium": 4,
    "Low": 2,
    "Informational": 0
}


def calculate_raw_score(findings):
    """
    Calculate the raw risk score from findings.
    """

    score = 0

    for finding in findings:

        severity = finding.get(
            "severity",
            "Informational"
        )

        score += SEVERITY_POINTS.get(
            severity,
            0
        )

    return score


def calculate_risk_score(findings):
    """
    Convert findings into a normalized 0-100 risk score.
    """

    raw_score = calculate_raw_score(findings)

    # Maximum contribution used for normalization.
    #
    # This keeps the score within 0-100 while allowing
    # multiple findings to contribute.
    maximum_score = max(
        100,
        len(findings) * 10
    )

    score = (raw_score / maximum_score) * 100

    score = round(
        min(score, 100),
        2
    )

    return score


def get_risk_level(score):
    """
    Convert numerical risk score into a risk level.
    """

    if score >= 75:
        return "Critical"

    if score >= 50:
        return "High"

    if score >= 25:
        return "Medium"

    if score > 0:
        return "Low"

    return "Informational"


def generate_risk_report(findings):
    """
    Generate complete risk assessment.
    """

    raw_score = calculate_raw_score(findings)

    score = calculate_risk_score(findings)

    level = get_risk_level(score)

    return {
        "raw_score": raw_score,
        "risk_score": score,
        "risk_level": level
    }
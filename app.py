import json

from flask import (
    Flask,
    jsonify,
    redirect,
    render_template,
    request
)
from flask_cors import CORS
from flask_session import Session

from config import Config

from database.db import (
    initialize_database,
    save_scan,
    get_scan_history,
    get_scan_by_id,
    save_audit_log
)

from services.rule_engine import (
    scan_with_rules
)

from services.gemini_service import (
    get_gemini_service
)

from services.scoring import (
    create_score_response
)

from services.prompt_optimizer import (
    optimize_prompt
)

from utils.helpers import (
    is_valid_prompt,
    sanitize_prompt,
    safe_json_dumps
)


# -------------------------------------------------------------------
# Application setup
# -------------------------------------------------------------------

app = Flask(
    __name__
)

app.config.from_object(
    Config
)

app.config["SESSION_TYPE"] = "filesystem"

CORS(
    app,
    resources={
        r"/api/*": {
            "origins": "*"
        }
    }
)

Session(app)


# -------------------------------------------------------------------
# Database initialization
# -------------------------------------------------------------------

initialize_database()


# -------------------------------------------------------------------
# Basic health endpoint
# -------------------------------------------------------------------

@app.route("/")
def index():
    """
    Main frontend page.
    """

    return render_template(
        "index.html"
    )

@app.route("/scanner")
def scanner():
    return render_template(
        "dashboard.html",
        workspace_mode="scanner"
    )


@app.route("/assessment")
def assessment():
    return render_template(
        "dashboard.html",
        workspace_mode="assessment"
    )


@app.route("/optimization")
def optimization():
    return render_template(
        "dashboard.html",
        workspace_mode="optimization"
    )


@app.route("/dashboard")
def dashboard():
    return redirect("/scanner")


@app.route("/api/health", methods=["GET"])
def health():
    """
    Basic health check endpoint.

    Useful for testing local and cloud deployment.
    """

    return jsonify(
        {
            "status": "ok",
            "service": "Prompt Shield",
            "message": "Prompt Shield API is running."
        }
    )


def rule_only_analysis(rule_result, reason):
    return {
        "threat_type": rule_result["threat_type"],
        "confidence": 0.0,
        "threat_weight": 0.0,
        "available": False,
        "explanation": (
            "AI semantic analysis is unavailable because "
            f"{reason}. The rule-based assessment completed successfully."
        )
    }


# -------------------------------------------------------------------
# Scan endpoint
# -------------------------------------------------------------------

@app.route("/api/scan", methods=["POST"])
def scan_prompt():
    """
    Main Prompt Shield scanning endpoint.

    Workflow:

    1. Receive prompt
    2. Validate prompt
    3. Run rule based scanner
    4. Run Gemini semantic analysis
    5. Calculate weighted security score
    6. Generate explanation
    7. Optimize risky prompt if required
    8. Save result to SQLite
    9. Return structured JSON
    """

    try:

        data = request.get_json(
            silent=True
        )

        if not data:
            return jsonify(
                {
                    "success": False,
                    "error": "Request body must contain JSON."
                }
            ), 400

        prompt = data.get(
            "prompt"
        )

        if not is_valid_prompt(prompt):
            return jsonify(
                {
                    "success": False,
                    "error": "Please provide a valid prompt."
                }
            ), 400

        prompt = sanitize_prompt(
            prompt
        )

        if len(prompt) > Config.MAX_PROMPT_LENGTH:
            return jsonify(
                {
                    "success": False,
                    "error": (
                        f"Prompt exceeds the maximum allowed "
                        f"length of {Config.MAX_PROMPT_LENGTH} characters."
                    )
                }
            ), 400

        # -----------------------------------------------------------
        # Stage 1: Rule based analysis
        # -----------------------------------------------------------

        rule_result = scan_with_rules(
            prompt
        )

        # -----------------------------------------------------------
        # Stage 2: Gemini semantic analysis
        # -----------------------------------------------------------

        if Config.GEMINI_API_KEY:
            try:
                gemini_service = get_gemini_service()
                llm_result = gemini_service.analyze_prompt(
                    prompt,
                    rule_result
                )
                llm_result["available"] = True
            except Exception as error:
                print(f"[WARN] Gemini scan unavailable: {error}")
                llm_result = rule_only_analysis(
                    rule_result,
                    "the Gemini service could not be reached"
                )
        else:
            llm_result = rule_only_analysis(
                rule_result,
                "GEMINI_API_KEY is not configured"
            )

        # -----------------------------------------------------------
        # Stage 3: Weighted security score
        # -----------------------------------------------------------

        score_result = create_score_response(
            rule_result,
            llm_result
        )

        security_score = score_result[
            "score"
        ]

        # -----------------------------------------------------------
        # Stage 4: Prompt optimization
        # -----------------------------------------------------------

        optimized_prompt = None

        optimization_applied = False

        if (
            security_score is not None and
            security_score >= Config.OPTIMIZE_THRESHOLD
        ):

            optimized_prompt = optimize_prompt(
                prompt,
                {
                    **llm_result,
                    "score": security_score
                }
            )

            optimization_applied = True

        # -----------------------------------------------------------
        # Stage 5: Save to database
        # -----------------------------------------------------------

        scan_data = {
            "prompt": prompt,

            "rule_score": score_result[
                "rule_score"
            ],

            "llm_confidence": score_result[
                "llm_confidence"
            ],

            "threat_weight": score_result[
                "threat_weight"
            ],

            "security_score": (
                security_score
                if security_score is not None
                else 0
            ),

            "risk_category": score_result[
                "risk_category"
            ],

            "threat_type": score_result[
                "threat_type"
            ],

            "rule_findings": safe_json_dumps(
                rule_result.get(
                    "findings",
                    []
                )
            ),

            "llm_explanation": llm_result.get(
                "explanation",
                ""
            ),

            "explanation": score_result[
                "explanation"
            ],

            "optimized_prompt": optimized_prompt,

            "optimization_applied": optimization_applied
        }

        scan_id = save_scan(
            scan_data
        )

        # -----------------------------------------------------------
        # Audit log
        # -----------------------------------------------------------

        save_audit_log(
            action="PROMPT_SCAN",
            endpoint="/api/scan",
            ip_address=request.remote_addr,
            details=json.dumps(
                {
                    "scan_id": scan_id,
                    "risk_category": score_result[
                        "risk_category"
                    ],
                    "threat_type": score_result[
                        "threat_type"
                    ]
                }
            )
        )

        # -----------------------------------------------------------
        # Final response
        # -----------------------------------------------------------

        return jsonify(
            {
                "success": True,

                "scan_id": scan_id,

                "prompt": prompt,

                "security_score": security_score,

                "risk_category": score_result[
                    "risk_category"
                ],

                "assessment_status": score_result[
                    "assessment_status"
                ],

                "threat_type": score_result[
                    "threat_type"
                ],

                "rule_analysis": {
                    "matched": rule_result[
                        "matched"
                    ],
                    "score": rule_result[
                        "rule_score"
                    ],
                    "findings": rule_result[
                        "findings"
                    ]
                },

                "llm_analysis": {
                    "confidence": llm_result[
                        "confidence"
                    ],
                    "threat_weight": llm_result[
                        "threat_weight"
                    ],
                    "explanation": llm_result[
                        "explanation"
                    ],
                    "available": llm_result.get(
                        "available",
                        True
                    )
                },

                "scoring": {
                    "rule_component": score_result[
                        "rule_component"
                    ],
                    "llm_component": score_result[
                        "llm_component"
                    ]
                },

                "explanation": score_result[
                    "explanation"
                ],

                "optimized_prompt": optimized_prompt,

                "optimization_applied": optimization_applied
            }
        )

    except ValueError as error:

        return jsonify(
            {
                "success": False,
                "error": str(error)
            }
        ), 500

    except Exception as error:

        print(
            f"[ERROR] /api/scan: {error}"
        )

        return jsonify(
            {
                "success": False,
                "error": (
                    "An unexpected error occurred while "
                    "processing the prompt."
                )
            }
        ), 500


# -------------------------------------------------------------------
# History endpoint
# -------------------------------------------------------------------

@app.route("/api/history", methods=["GET"])
def history():
    """
    Return recent scan history.
    """

    try:

        limit = request.args.get(
            "limit",
            default=50,
            type=int
        )

        limit = max(
            1,
            min(limit, 100)
        )

        scans = get_scan_history(
            limit=limit
        )

        return jsonify(
            {
                "success": True,
                "count": len(scans),
                "scans": scans
            }
        )

    except Exception as error:

        print(
            f"[ERROR] /api/history: {error}"
        )

        return jsonify(
            {
                "success": False,
                "error": "Unable to retrieve scan history."
            }
        ), 500


# -------------------------------------------------------------------
# Single scan endpoint
# -------------------------------------------------------------------

@app.route("/api/history/<int:scan_id>", methods=["GET"])
def single_scan(scan_id):
    """
    Return one saved scan.
    """

    scan = get_scan_by_id(
        scan_id
    )

    if scan is None:

        return jsonify(
            {
                "success": False,
                "error": "Scan not found."
            }
        ), 404

    return jsonify(
        {
            "success": True,
            "scan": scan
        }
    )


# -------------------------------------------------------------------
# Standalone optimization endpoint
# -------------------------------------------------------------------

@app.route("/api/optimize", methods=["POST"])
def optimize():
    """
    Optimize a prompt independently from the main scan endpoint.
    """

    try:

        data = request.get_json(
            silent=True
        )

        if not data:

            return jsonify(
                {
                    "success": False,
                    "error": "Request body must contain JSON."
                }
            ), 400

        prompt = data.get(
            "prompt"
        )

        if not is_valid_prompt(prompt):

            return jsonify(
                {
                    "success": False,
                    "error": "Please provide a valid prompt."
                }
            ), 400

        prompt = sanitize_prompt(
            prompt
        )

        if len(prompt) > Config.MAX_PROMPT_LENGTH:

            return jsonify(
                {
                    "success": False,
                    "error": (
                        f"Prompt exceeds the maximum allowed "
                        f"length of {Config.MAX_PROMPT_LENGTH} characters."
                    )
                }
            ), 400

        rule_result = scan_with_rules(
            prompt
        )

        if Config.GEMINI_API_KEY:
            try:
                gemini_service = get_gemini_service()
                llm_result = gemini_service.analyze_prompt(
                    prompt,
                    rule_result
                )
                llm_result["available"] = True
            except Exception as error:
                print(f"[WARN] Gemini optimization analysis unavailable: {error}")
                llm_result = rule_only_analysis(
                    rule_result,
                    "the Gemini service could not be reached"
                )
        else:
            llm_result = rule_only_analysis(
                rule_result,
                "GEMINI_API_KEY is not configured"
            )

        optimized = optimize_prompt(
            prompt,
            llm_result
        )

        return jsonify(
            {
                "success": True,
                "original_prompt": prompt,
                "optimized_prompt": optimized,
                "threat_type": llm_result[
                    "threat_type"
                ],
                "confidence": llm_result[
                    "confidence"
                ]
            }
        )

    except Exception as error:

        print(
            f"[ERROR] /api/optimize: {error}"
        )

        return jsonify(
            {
                "success": False,
                "error": (
                    "Unable to optimize the prompt."
                )
            }
        ), 500


# -------------------------------------------------------------------
# Application entry point
# -------------------------------------------------------------------

if __name__ == "__main__":

    print()
    print("=" * 60)
    print("PROMPT SHIELD")
    print("AI Prompt Security & Optimization Platform")
    print("=" * 60)
    print()
    print("Server starting...")
    print("Open: http://127.0.0.1:5000")
    print()

    app.run(
        host="127.0.0.1",
        port=5000,
        debug=True
    )



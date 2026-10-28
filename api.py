
import os
from typing import Literal

from fastapi import FastAPI, Header, HTTPException, Query
from pydantic import BaseModel, Field

from governiq_core import (
    load_policy,
    evaluate,
    execute_demo,
    audit,
    audit_events,
    verify_audit,
)

# --------------------------------------------------
# Configuration
# --------------------------------------------------

API_KEY = os.getenv("GOVERNIQ_API_KEY", "").strip()

app = FastAPI(
    title="GovernIQ Policy Gateway",
    version="2.1.0",
    description=(
        "AI agent governance gateway that evaluates tool requests "
        "against policy rules before executing simulated tools."
    ),
)


# --------------------------------------------------
# Request schema
# --------------------------------------------------

class EvaluationRequest(BaseModel):
    tool: str = Field(min_length=1, max_length=100)
    input: str = Field(max_length=10000)
    mode: Literal["Open", "Standard", "Strict", "Locked"] = "Standard"
    session_id: str = Field(default="demo", min_length=1, max_length=100)
    approved: bool = False


# --------------------------------------------------
# Authentication
# --------------------------------------------------

def verify_api_key(x_api_key: str | None) -> None:
    """Require a valid API key when authentication is configured."""
    if API_KEY and x_api_key != API_KEY:
        raise HTTPException(
            status_code=401,
            detail="Invalid or missing API key.",
        )


# --------------------------------------------------
# Health check
# --------------------------------------------------

@app.get("/health", tags=["System"])
def health_check():
    return {
        "status": "ok",
        "service": "GovernIQ",
        "version": app.version,
        "tools": "simulated",
    }


# --------------------------------------------------
# Policy configuration
# --------------------------------------------------

@app.get("/policy", tags=["Policy"])
def get_policy(
    x_api_key: str | None = Header(default=None),
):
    verify_api_key(x_api_key)

    try:
        return load_policy()
    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail="Unable to load governance policy.",
        ) from exc


# --------------------------------------------------
# Evaluate a tool request
# --------------------------------------------------

@app.post("/evaluate", tags=["Evaluation"])
def evaluate_request(
    request: EvaluationRequest,
    x_api_key: str | None = Header(default=None),
):
    verify_api_key(x_api_key)

    result = evaluate(
        request.tool,
        request.input,
        request.mode,
        calls_used=0,
        approval_recheck=request.approved,
    )

    decision = result.get("decision")

    # Execute only when the policy engine allows the request.
    if decision == "ALLOW":
        try:
            result["output"] = execute_demo(
                request.tool,
                request.input,
            )
        except PermissionError as exc:
            result["decision"] = "DENY"
            result["reason"] = str(exc)
            result.pop("output", None)
        except Exception:
            # Do not expose internal exception details to API clients.
            result["decision"] = "ERROR"
            result["reason"] = "Demo tool execution failed."
            result.pop("output", None)

    # Record the final decision, not just the initial policy result.
    try:
        audit(
            "api_response",
            {
                "session_id": request.session_id,
                "tool": request.tool,
                "mode": request.mode,
                "decision": result.get("decision", "UNKNOWN"),
            },
        )
    except Exception as exc:
        # Fail closed if the audit system is unavailable.
        raise HTTPException(
            status_code=500,
            detail="Unable to record the governance audit event.",
        ) from exc

    return result


# --------------------------------------------------
# Audit integrity verification
# --------------------------------------------------

@app.get("/audit/verify", tags=["Audit"])
def verify_audit_chain(
    x_api_key: str | None = Header(default=None),
):
    verify_api_key(x_api_key)

    try:
        return verify_audit()
    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail="Unable to verify audit integrity.",
        ) from exc


# --------------------------------------------------
# Audit event history
# --------------------------------------------------

@app.get("/audit/events", tags=["Audit"])
def get_audit_events(
    limit: int = Query(default=100, ge=1, le=1000),
    x_api_key: str | None = Header(default=None),
):
    verify_api_key(x_api_key)

    try:
        return audit_events(limit)
    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail="Unable to retrieve audit events.",
        ) from exc

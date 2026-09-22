import os
import time

from google import genai
from google.genai import types
from pydantic import BaseModel
from google.genai.errors import ClientError, ServerError

PROVIDER_NAME = "Google Gemini"
MODEL_NAME = "gemini-3.6-flash"

# The provider answers 503 UNAVAILABLE itself ("high demand ... usually
# temporary") on this model. A short bounded retry handles transient spikes;
# anything persistent still ends in the friendly message below — never a
# partial record (retries happen before any DB write) and never a lifecycle
# change. No retry on non-5xx errors.
AI_GENERATION_ATTEMPTS = 3
AI_RETRY_BASE_DELAY_SECONDS = 5

# Structured analysis can be slow; 30s cut off responses that would have
# succeeded. (Tiny connection pings keep the shorter timeout.)
AI_GENERATION_TIMEOUT_MS = 60000

# User-friendly message for provider overload (HTTP 503 UNAVAILABLE).
# Never expose raw provider internals for this case.
PROVIDER_UNAVAILABLE_MESSAGE = (
    "AI service is temporarily unavailable. Please try again later."
)

# User-friendly message for daily quota exhaustion (HTTP 429
# RESOURCE_EXHAUSTED). Quota does not clear by retrying, so it is returned
# immediately with no retry. No quota internals are exposed.
QUOTA_EXHAUSTED_MESSAGE = (
    "AI service quota is temporarily unavailable. Please try again later."
)

class VulnerabilityAIResponse(BaseModel):
    explanation: str
    potential_impact: str
    remediation_steps: str
    verification_steps: str

def test_gemini_connection():
    """Test whether CyberShield can communicate with the Gemini API."""
    api_key = os.getenv("GEMINI_API_KEY")

    if not api_key:
        return {
            "success": False,
            "error": "GEMINI_API_KEY is not configured."
        }

    try:
        client = genai.Client(
            api_key=api_key,
            http_options=types.HttpOptions(timeout=30000),
        )

        response = client.models.generate_content(
            model=MODEL_NAME,
            contents="Reply with the word: ok",
        )

        return {
            "success": True,
            "reply": (response.text or "").strip(),
        }

    except ServerError as error:
        return {
            "success": False,
            "error": PROVIDER_UNAVAILABLE_MESSAGE,
    }

    except Exception as error:
        return {
            "success": False,
            "error": "AI connection test failed. Please try again later.",
        }

def analyze_vulnerability(vulnerability):
    """Generate AI-assisted security guidance for a vulnerability."""

    try:
        finding = vulnerability.finding
    except Exception:
        finding = None

    vulnerability_context = {
        "title": vulnerability.title,
        "description": vulnerability.description,
        "severity": vulnerability.severity,
        "impact": vulnerability.impact,
        "likelihood": vulnerability.likelihood,
        "risk_score": vulnerability.risk_score,
        "risk_level": vulnerability.risk_level,
        "cwe_id": finding.cwe_id if finding else "",
    }

    prompt = f"""
    You are the AI Security Assistant for CyberShield, a vulnerability
    management platform.

    Analyze the following confirmed vulnerability:

    Title: {vulnerability_context['title']}
    Description: {vulnerability_context['description']}
    Severity: {vulnerability_context['severity']}
    Impact: {vulnerability_context['impact']}/5
    Likelihood: {vulnerability_context['likelihood']}/5
    Risk Score: {vulnerability_context['risk_score']}/25
    Risk Level: {vulnerability_context['risk_level']}
    CWE: {vulnerability_context['cwe_id']}

    Provide practical defensive guidance for a security analyst.

    Return the analysis in exactly these four sections:

    EXPLANATION:
    Explain the vulnerability clearly and concisely.

    POTENTIAL_IMPACT:
    Describe what could happen if the vulnerability is successfully exploited.

    REMEDIATION_STEPS:
    Provide concrete defensive steps to remediate the vulnerability.

    VERIFICATION_STEPS:
    Explain how the security team can safely verify that the vulnerability
    has been remediated.

    Do not provide offensive exploitation instructions, payloads, credentials,
    or destructive actions.
    """

    api_key = os.getenv("GEMINI_API_KEY")

    if not api_key:
        return {
            "success": False,
            "error": "GEMINI_API_KEY is not configured."
        }

    client = genai.Client(
        api_key=api_key,
        http_options=types.HttpOptions(timeout=AI_GENERATION_TIMEOUT_MS),
    )
    config = types.GenerateContentConfig(
        response_mime_type="application/json",
        response_schema=VulnerabilityAIResponse,
    )

    for attempt in range(1, AI_GENERATION_ATTEMPTS + 1):
        try:
            response = client.models.generate_content(
                model=MODEL_NAME,
                contents=prompt,
                config=config,
            )

            parsed = getattr(response, "parsed", None)
            if parsed is None:
                return {
                    "success": False,
                    "error": "AI service returned an invalid response. Please try again later.",
                }

            analysis = parsed.model_dump()
            required = ("explanation", "potential_impact", "remediation_steps", "verification_steps")
            if any(not str(analysis.get(field) or "").strip() for field in required):
                return {
                    "success": False,
                    "error": "AI service returned an incomplete response. Please try again later.",
                }

            return {
                "success": True,
                "analysis": analysis,
            }

        except ServerError as error:
            if attempt < AI_GENERATION_ATTEMPTS:
                time.sleep(AI_RETRY_BASE_DELAY_SECONDS * attempt)
                continue
            return {
                "success": False,
                "error": PROVIDER_UNAVAILABLE_MESSAGE,
            }

        except ClientError as error:
            # Daily quota exhaustion must not be retried blindly; other 4xx
            # failures would not heal by retrying either. Safe message only.
            if getattr(error, "code", None) == 429:
                return {
                    "success": False,
                    "error": QUOTA_EXHAUSTED_MESSAGE,
                }
            return {
                "success": False,
                "error": "AI generation failed. Please try again later.",
            }

        except Exception as error:
            return {
                "success": False,
                "error": "AI generation failed. Please try again later.",
            }
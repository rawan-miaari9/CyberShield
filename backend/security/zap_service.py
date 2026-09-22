import hashlib
import os

import requests

from .models import SecurityFinding


def test_zap_connection():
    """Test whether CyberShield can connect to the configured ZAP instance."""

    base_url = os.getenv("ZAP_BASE_URL")
    api_key = os.getenv("ZAP_API_KEY")

    try:
        response = requests.get(
            f"{base_url}/JSON/core/view/version/",
            params={"apikey": api_key},
            timeout=5,
        )

        response.raise_for_status()

        data = response.json()

        return {
            "success": True,
            "version": data.get("version"),
        }

    except requests.RequestException as error:
        return {
            "success": False,
            "error": str(error),
        }

def fetch_zap_alerts(base_url=None):
    """Fetch alerts from the configured ZAP instance."""

    zap_url = os.getenv("ZAP_BASE_URL")
    api_key = os.getenv("ZAP_API_KEY")

    params = {
        "apikey": api_key,
    }

    if base_url:
        params["baseurl"] = base_url

    try:
        response = requests.get(
            f"{zap_url}/JSON/core/view/alerts/",
            params=params,
            timeout=10,
        )

        response.raise_for_status()

        data = response.json()

        return {
            "success": True,
            "alerts": data.get("alerts", []),
        }

    except requests.RequestException as error:
        return {
            "success": False,
            "alerts": [],
            "error": str(error),
        }

def normalize_zap_alert(alert):
    """Convert one raw ZAP alert into CyberShield SecurityFinding format."""

    severity_map = {
        "Informational": "INFO",
        "Low": "LOW",
        "Medium": "MEDIUM",
        "High": "HIGH",
        "Critical": "CRITICAL",
    }

    severity = severity_map.get(
        alert.get("risk", ""),
        "INFO"
    )

    return {
        "external_id": str(
            alert.get("messageId")
            or alert.get("id")
            or ""
        ),
        "title": alert.get("name") or alert.get("alert") or "Unknown ZAP Alert",
        "description": alert.get("description", ""),
        "severity": severity,
        "confidence": alert.get("confidence", ""),
        "cwe_id": str(alert.get("cweid", "")),
        "evidence": alert.get("evidence", ""),
        "source_url": alert.get("url", ""),
        "raw_data": alert,
    }
def generate_zap_fingerprint(alert):
    """Generate a stable fingerprint for duplicate detection."""

    fingerprint_source = "|".join([
        str(alert.get("pluginId") or alert.get("alertRef") or ""),
        alert.get("url", ""),
        alert.get("param", ""),
        alert.get("method", ""),
    ])

    return hashlib.sha256(
        fingerprint_source.encode("utf-8")
    ).hexdigest()

def save_zap_finding(alert, integration, asset):
    """Save one normalized ZAP alert as a CyberShield SecurityFinding."""

    normalized = normalize_zap_alert(alert)
    fingerprint = generate_zap_fingerprint(alert)

    finding, created = SecurityFinding.objects.get_or_create(
        integration=integration,
        fingerprint=fingerprint,
        defaults={
            "asset": asset,
            "external_id": normalized["external_id"],
            "title": normalized["title"],
            "description": normalized["description"],
            "severity": normalized["severity"],
            "confidence": normalized["confidence"],
            "cwe_id": normalized["cwe_id"],
            "evidence": normalized["evidence"],
            "source_url": normalized["source_url"],
            "status": "NEW",
            "raw_data": normalized["raw_data"],
        },
    )

    return finding, created

def sync_zap_findings(integration, asset):
    """Fetch ZAP alerts and synchronize them with CyberShield."""

    result = fetch_zap_alerts(asset.url)

    if not result["success"]:
        return {
            "success": False,
            "created": 0,
            "duplicates": 0,
            "error": result.get("error", "Unable to fetch ZAP alerts"),
        }

    created_count = 0
    duplicate_count = 0

    for alert in result["alerts"]:
        finding, created = save_zap_finding(
            alert,
            integration,
            asset,
        )

        if created:
            created_count += 1
        else:
            duplicate_count += 1

    return {
        "success": True,
        "total": len(result["alerts"]),
        "created": created_count,
        "duplicates": duplicate_count,
    }
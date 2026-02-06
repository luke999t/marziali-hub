"""
AI_MODULE: Stripe Production Checklist
AI_DESCRIPTION: Verifica configurazione Stripe per produzione
AI_BUSINESS: Evita errori pagamenti in produzione, compliance PCI
AI_TEACHING: Stripe API validation, webhook signatures, idempotency

ALTERNATIVE_VALUTATE:
- Manual checklist: Scartato, error-prone
- External monitoring: Scartato, non cattura config errors
- Post-deploy check: Scartato, troppo tardi

PERCHE_QUESTA_SOLUZIONE:
- Pre-deploy validation: Cattura errori prima di produzione
- Automated checks: Consistente e ripetibile
- Clear reporting: Facile identificare problemi

METRICHE_SUCCESSO:
- Config errors caught: 100%
- False positives: <1%
- Check time: <5s
"""

import os
from typing import Dict, List, Any, Tuple
from datetime import datetime

# Try to import stripe, graceful fallback if not installed
STRIPE_AVAILABLE = False
try:
    import stripe
    STRIPE_AVAILABLE = True
except ImportError:
    stripe = None


def check_stripe_production_ready() -> Dict[str, Any]:
    """
    Verifica che Stripe sia configurato correttamente per produzione.

    Checks:
    1. API key presente e formato corretto
    2. Webhook secret configurato
    3. Publishable key per frontend
    4. Connessione API funzionante
    5. Prezzi/prodotti configurati

    Returns:
        Dict con:
        - ready: bool - True se pronto per produzione
        - issues: List[str] - Problemi critici
        - warnings: List[str] - Avvisi non bloccanti
        - mode: str - "LIVE" o "TEST"
        - details: Dict - Dettagli aggiuntivi
    """
    issues: List[str] = []
    warnings: List[str] = []
    details: Dict[str, Any] = {}

    # Check if stripe library is available
    if not STRIPE_AVAILABLE:
        issues.append("stripe library non installata - pip install stripe")
        return {
            "ready": False,
            "issues": issues,
            "warnings": warnings,
            "mode": "UNKNOWN",
            "details": details
        }

    # 1. Verifica API key
    api_key = os.getenv("STRIPE_SECRET_KEY", "")
    if not api_key:
        issues.append("STRIPE_SECRET_KEY non configurata")
    elif api_key.startswith("sk_test_"):
        warnings.append("Stai usando TEST key, non LIVE - OK per development")
        details["mode"] = "TEST"
    elif api_key.startswith("sk_live_"):
        details["mode"] = "LIVE"
    else:
        issues.append("STRIPE_SECRET_KEY formato non valido (deve iniziare con sk_test_ o sk_live_)")

    # 2. Verifica webhook secret
    webhook_secret = os.getenv("STRIPE_WEBHOOK_SECRET", "")
    if not webhook_secret:
        issues.append("STRIPE_WEBHOOK_SECRET non configurata - webhooks non funzioneranno")
    elif not webhook_secret.startswith("whsec_"):
        issues.append("STRIPE_WEBHOOK_SECRET formato non valido (deve iniziare con whsec_)")
    else:
        details["webhook_configured"] = True

    # 3. Verifica publishable key per frontend
    pub_key = os.getenv("STRIPE_PUBLISHABLE_KEY", "")
    if not pub_key:
        warnings.append("STRIPE_PUBLISHABLE_KEY non configurata (necessaria per frontend)")
    elif not pub_key.startswith(("pk_test_", "pk_live_")):
        warnings.append("STRIPE_PUBLISHABLE_KEY formato non standard")
    else:
        # Verifica coerenza test/live
        api_is_live = api_key.startswith("sk_live_")
        pub_is_live = pub_key.startswith("pk_live_")
        if api_is_live != pub_is_live:
            issues.append("MISMATCH: API key e publishable key devono essere entrambe TEST o LIVE")
        details["publishable_key_configured"] = True

    # 4. Test connessione API (solo se abbiamo una key)
    if api_key:
        try:
            stripe.api_key = api_key
            account = stripe.Account.retrieve()
            details["account_id"] = account.id
            details["account_email"] = account.get("email")
            details["account_country"] = account.get("country")
            details["charges_enabled"] = account.get("charges_enabled")
            details["payouts_enabled"] = account.get("payouts_enabled")

            if not account.get("charges_enabled"):
                warnings.append("Account Stripe: charges non abilitati")
            if not account.get("payouts_enabled"):
                warnings.append("Account Stripe: payouts non abilitati")

        except stripe.error.AuthenticationError:
            issues.append("API key non valida - autenticazione fallita")
        except stripe.error.APIConnectionError as e:
            warnings.append(f"Connessione API fallita: {str(e)}")
        except Exception as e:
            warnings.append(f"Errore verifica account: {str(e)}")

    # 5. Verifica prezzi/prodotti configurati
    required_prices = {
        "STRIPE_PRICE_PREMIUM_MONTHLY": "Abbonamento Premium mensile",
        "STRIPE_PRICE_PREMIUM_YEARLY": "Abbonamento Premium annuale",
        "STRIPE_PRICE_PPV_BASE": "Pay-per-view base (opzionale)",
    }

    for price_env, description in required_prices.items():
        price_id = os.getenv(price_env)
        if not price_id:
            if "opzionale" not in description.lower():
                warnings.append(f"{price_env} non configurato ({description})")
        elif api_key:
            # Verifica che il prezzo esista
            try:
                price = stripe.Price.retrieve(price_id)
                details[f"price_{price_env}"] = {
                    "id": price.id,
                    "active": price.active,
                    "currency": price.currency,
                    "unit_amount": price.unit_amount
                }
                if not price.active:
                    warnings.append(f"Prezzo {price_env} non è attivo su Stripe")
            except stripe.error.InvalidRequestError:
                issues.append(f"Prezzo {price_env} non esiste su Stripe: {price_id}")
            except Exception as e:
                warnings.append(f"Errore verifica prezzo {price_env}: {str(e)}")

    # 6. Verifica webhook endpoint configurato (se in LIVE mode)
    if details.get("mode") == "LIVE":
        if not os.getenv("STRIPE_WEBHOOK_ENDPOINT_URL"):
            warnings.append("STRIPE_WEBHOOK_ENDPOINT_URL non configurato per LIVE mode")

    # 7. Determina stato finale
    mode = details.get("mode", "TEST" if api_key.startswith("sk_test_") else "UNKNOWN")

    return {
        "ready": len(issues) == 0,
        "issues": issues,
        "warnings": warnings,
        "mode": mode,
        "details": details,
        "checked_at": datetime.utcnow().isoformat()
    }


async def stripe_health_check() -> Dict[str, Any]:
    """
    Endpoint health check per admin.

    Usato da:
    - GET /api/v1/admin/stripe/health
    - Monitoring systems
    - Pre-deploy checks
    """
    result = check_stripe_production_ready()

    # Aggiungi info ambiente
    result["environment"] = os.getenv("ENVIRONMENT", "development")

    # Semplifica per response HTTP
    return {
        "status": "healthy" if result["ready"] else "unhealthy",
        "mode": result["mode"],
        "issues_count": len(result["issues"]),
        "warnings_count": len(result["warnings"]),
        "issues": result["issues"],
        "warnings": result["warnings"],
        "details": result["details"],
        "checked_at": result["checked_at"]
    }


def get_stripe_dashboard_url() -> str:
    """Ritorna URL dashboard Stripe basato su mode."""
    api_key = os.getenv("STRIPE_SECRET_KEY", "")
    if api_key.startswith("sk_live_"):
        return "https://dashboard.stripe.com"
    return "https://dashboard.stripe.com/test"


def validate_webhook_signature(payload: bytes, sig_header: str) -> Tuple[bool, str]:
    """
    Valida firma webhook Stripe.

    Args:
        payload: Body raw della richiesta
        sig_header: Header Stripe-Signature

    Returns:
        Tuple (is_valid, error_message)
    """
    if not STRIPE_AVAILABLE:
        return False, "Stripe library not available"

    webhook_secret = os.getenv("STRIPE_WEBHOOK_SECRET")
    if not webhook_secret:
        return False, "Webhook secret not configured"

    try:
        event = stripe.Webhook.construct_event(
            payload, sig_header, webhook_secret
        )
        return True, ""
    except stripe.error.SignatureVerificationError as e:
        return False, f"Invalid signature: {str(e)}"
    except Exception as e:
        return False, f"Validation error: {str(e)}"


# CLI per testing manuale
if __name__ == "__main__":
    import json

    print("\n" + "=" * 60)
    print("  STRIPE PRODUCTION READINESS CHECK")
    print("=" * 60 + "\n")

    result = check_stripe_production_ready()

    # Status
    if result["ready"]:
        print("  STATUS: READY for production")
    else:
        print("  STATUS: NOT READY - fix issues below")

    print(f"  MODE: {result['mode']}")
    print()

    # Issues
    if result["issues"]:
        print("  ISSUES (must fix):")
        for issue in result["issues"]:
            print(f"    {issue}")
        print()

    # Warnings
    if result["warnings"]:
        print("  WARNINGS (should review):")
        for warning in result["warnings"]:
            print(f"    {warning}")
        print()

    # Details
    if result["details"]:
        print("  DETAILS:")
        print(json.dumps(result["details"], indent=4))

    print("\n" + "=" * 60 + "\n")

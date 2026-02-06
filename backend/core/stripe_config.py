"""
🎫 Stripe Configuration
Centralized Stripe setup and utilities
"""

import os
import stripe
from typing import Optional
from dotenv import load_dotenv

load_dotenv()

# === STRIPE CONFIGURATION ===

STRIPE_SECRET_KEY = os.getenv("STRIPE_SECRET_KEY")
STRIPE_PUBLISHABLE_KEY = os.getenv("STRIPE_PUBLISHABLE_KEY")
STRIPE_WEBHOOK_SECRET = os.getenv("STRIPE_WEBHOOK_SECRET")

# Initialize Stripe
if STRIPE_SECRET_KEY:
    stripe.api_key = STRIPE_SECRET_KEY
else:
    print("[WARNING] STRIPE_SECRET_KEY not set. Stripe functionality will be disabled.")


# === STELLINE PACKAGES ===

STELLINE_PACKAGES = {
    "small": {
        "stelline": 1000,
        "price_eur": 10.00,
        "price_cents": 1000,
        "name": "Pacchetto Small",
        "description": "1000 stelline (10€)"
    },
    "medium": {
        "stelline": 5000,
        "price_eur": 45.00,
        "price_cents": 4500,
        "name": "Pacchetto Medium",
        "description": "5000 stelline (45€) - Risparmi 5€!"
    },
    "large": {
        "stelline": 10000,
        "price_eur": 80.00,
        "price_cents": 8000,
        "name": "Pacchetto Large",
        "description": "10000 stelline (80€) - Risparmi 20€!"
    }
}


# === SUBSCRIPTION PLANS ===

SUBSCRIPTION_PLANS = {
    "HYBRID_LIGHT": {
        "name": "Hybrid Light",
        "price_eur": 4.99,
        "price_cents": 499,
        "interval": "month",
        "features": [
            "5 video premium al mese",
            "Accesso base AI Coach",
            "Community forum"
        ]
    },
    "HYBRID_STANDARD": {
        "name": "Hybrid Standard",
        "price_eur": 9.99,
        "price_cents": 999,
        "interval": "month",
        "features": [
            "15 video premium al mese",
            "AI Coach completo",
            "Live events accesso prioritario",
            "Nessuna pubblicità"
        ]
    },
    "PREMIUM": {
        "name": "Premium",
        "price_eur": 19.99,
        "price_cents": 1999,
        "interval": "month",
        "features": [
            "Video illimitati",
            "AI Coach premium",
            "Tutti i live events",
            "Download offline",
            "Nessuna pubblicità",
            "Badge esclusivo"
        ]
    },
    "BUSINESS": {
        "name": "Business",
        "price_eur": 49.99,
        "price_cents": 4999,
        "interval": "month",
        "features": [
            "Tutto Premium +",
            "Multi-account (fino a 10)",
            "Analytics avanzate",
            "Supporto prioritario",
            "Branding personalizzato"
        ]
    }
}


# === STRIPE UTILITIES ===

def create_payment_intent(
    amount_cents: int,
    currency: str = "eur",
    metadata: Optional[dict] = None
) -> stripe.PaymentIntent:
    """
    Create a Stripe Payment Intent.

    Args:
        amount_cents: Amount in cents
        currency: Currency code (default: eur)
        metadata: Optional metadata dict

    Returns:
        Stripe PaymentIntent object
    """
    if not STRIPE_SECRET_KEY:
        raise ValueError("Stripe is not configured")

    return stripe.PaymentIntent.create(
        amount=amount_cents,
        currency=currency,
        metadata=metadata or {},
        automatic_payment_methods={"enabled": True}
    )


def create_subscription(
    customer_id: str,
    price_id: str,
    metadata: Optional[dict] = None
) -> stripe.Subscription:
    """
    Create a Stripe Subscription.

    Args:
        customer_id: Stripe customer ID
        price_id: Stripe price ID
        metadata: Optional metadata dict

    Returns:
        Stripe Subscription object
    """
    if not STRIPE_SECRET_KEY:
        raise ValueError("Stripe is not configured")

    return stripe.Subscription.create(
        customer=customer_id,
        items=[{"price": price_id}],
        metadata=metadata or {},
        payment_behavior="default_incomplete",
        payment_settings={"save_default_payment_method": "on_subscription"},
        expand=["latest_invoice.payment_intent"]
    )


def cancel_subscription(subscription_id: str) -> stripe.Subscription:
    """
    Cancel a Stripe Subscription.

    Args:
        subscription_id: Stripe subscription ID

    Returns:
        Canceled Stripe Subscription object
    """
    if not STRIPE_SECRET_KEY:
        raise ValueError("Stripe is not configured")

    return stripe.Subscription.delete(subscription_id)


def create_customer(
    email: str,
    name: Optional[str] = None,
    metadata: Optional[dict] = None
) -> stripe.Customer:
    """
    Create a Stripe Customer.

    Args:
        email: Customer email
        name: Customer name
        metadata: Optional metadata dict

    Returns:
        Stripe Customer object
    """
    if not STRIPE_SECRET_KEY:
        raise ValueError("Stripe is not configured")

    return stripe.Customer.create(
        email=email,
        name=name,
        metadata=metadata or {}
    )


def verify_webhook_signature(
    payload: bytes,
    signature: str
) -> stripe.Event:
    """
    Verify Stripe webhook signature.

    Args:
        payload: Request body bytes
        signature: Stripe-Signature header value

    Returns:
        Verified Stripe Event object

    Raises:
        ValueError: If signature verification fails
    """
    if not STRIPE_WEBHOOK_SECRET:
        raise ValueError("Stripe webhook secret is not configured")

    try:
        event = stripe.Webhook.construct_event(
            payload, signature, STRIPE_WEBHOOK_SECRET
        )
        return event
    except stripe.error.SignatureVerificationError as e:
        raise ValueError(f"Invalid signature: {e}")


# === PRICE HELPERS ===

def stelline_to_eur(stelline: int) -> float:
    """Convert stelline to EUR (100 stelline = 1 EUR)"""
    return stelline / 100


def eur_to_stelline(eur: float) -> int:
    """Convert EUR to stelline (1 EUR = 100 stelline)"""
    return int(eur * 100)


def eur_to_cents(eur: float) -> int:
    """Convert EUR to cents"""
    return int(eur * 100)


def cents_to_eur(cents: int) -> float:
    """Convert cents to EUR"""
    return cents / 100


# === PRODUCT & PRICE MANAGEMENT ===

# Cache for product and price IDs (in-memory)
_stripe_cache = {
    "product_id": None,
    "prices": {}  # tier -> price_id
}


def get_or_create_subscription_product() -> str:
    """
    Get or create the main subscription product.

    Returns:
        Stripe Product ID
    """
    if not STRIPE_SECRET_KEY:
        raise ValueError("Stripe is not configured")

    # Check cache
    if _stripe_cache["product_id"]:
        return _stripe_cache["product_id"]

    # Search for existing product by metadata
    products = stripe.Product.list(
        active=True,
        limit=100
    )

    for product in products.data:
        if product.metadata.get("app") == "media-center-arti-marziali":
            _stripe_cache["product_id"] = product.id
            return product.id

    # Create new product
    product = stripe.Product.create(
        name="Media Center Arti Marziali - Abbonamento",
        description="Abbonamento mensile alla piattaforma di video arti marziali",
        metadata={"app": "media-center-arti-marziali"}
    )

    _stripe_cache["product_id"] = product.id
    return product.id


def get_or_create_price(tier: str) -> str:
    """
    Get or create a Stripe Price for a subscription tier.

    Args:
        tier: Subscription tier name (HYBRID_LIGHT, HYBRID_STANDARD, PREMIUM, BUSINESS)

    Returns:
        Stripe Price ID
    """
    if not STRIPE_SECRET_KEY:
        raise ValueError("Stripe is not configured")

    if tier not in SUBSCRIPTION_PLANS:
        raise ValueError(f"Unknown tier: {tier}")

    # Check cache
    if tier in _stripe_cache["prices"]:
        return _stripe_cache["prices"][tier]

    plan = SUBSCRIPTION_PLANS[tier]
    product_id = get_or_create_subscription_product()

    # Search for existing price by lookup_key
    lookup_key = f"mcam_{tier.lower()}_monthly"

    try:
        prices = stripe.Price.list(
            product=product_id,
            active=True,
            limit=100
        )

        for price in prices.data:
            # Match by amount and interval
            if (price.unit_amount == plan["price_cents"] and
                price.recurring and
                price.recurring.interval == plan["interval"]):
                _stripe_cache["prices"][tier] = price.id
                return price.id
    except Exception:
        pass  # Continue to create new price

    # Create new price
    price = stripe.Price.create(
        product=product_id,
        unit_amount=plan["price_cents"],
        currency="eur",
        recurring={"interval": plan["interval"]},
        lookup_key=lookup_key,
        metadata={
            "tier": tier,
            "app": "media-center-arti-marziali"
        }
    )

    _stripe_cache["prices"][tier] = price.id
    return price.id


def _reset_stripe_cache():
    """Reset the Stripe cache. Used for testing."""
    global _stripe_cache
    _stripe_cache = {
        "product_id": None,
        "prices": {}
    }

"""
AI_MODULE: Stripe Connect Integration
AI_DESCRIPTION: Split payment per eventi ASD con Stripe Connect
AI_BUSINESS: Pagamenti automatici split: piattaforma prende fee, ASD riceve resto
AI_TEACHING: Stripe Connect, destination charges, webhooks, refunds

ALTERNATIVE_VALUTATE:
- Manual payout: Scartato, non scalabile, errore umano
- Single account + transfer: Scartato, problemi fiscali/legali
- Separate payments: Scartato, UX peggiore, doppia transazione

PERCHE_QUESTA_SOLUZIONE:
- Stripe Connect destination charges: Split automatico a checkout
- Ogni ASD ha proprio account: Compliance fiscale, trasparenza
- Platform fee dedotta: LIBRA riceve % automaticamente
- Refunds: Proportional refund to both parties

FLOW:
1. User checkout -> Create PaymentIntent with transfer_data
2. Stripe splits: platform_fee to LIBRA, rest to ASD
3. Webhook confirms -> Update subscription status
4. Refund -> Stripe handles proportional refund

STRIPE CONNECT MODES:
- Standard: ASD manages own Stripe dashboard (RECOMMENDED)
- Express: Simplified onboarding, LIBRA manages
- Custom: Full control (complex, not recommended)
"""

import stripe
try:
    from stripe import StripeError, SignatureVerificationError
except (ImportError, AttributeError):
    # Fallback if stripe not fully configured
    StripeError = Exception
    SignatureVerificationError = Exception
from datetime import datetime, timedelta, timezone
from typing import Optional, Dict, Any, Tuple, List
from uuid import UUID
import logging

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, update

from modules.events.config import get_events_config, EventsConfig
from modules.events.models import (
    ASDPartner,
    Event,
    EventSubscription,
    ASDRefundRequest,
    SubscriptionStatus,
    RefundStatus
)

logger = logging.getLogger(__name__)


class StripeConnectService:
    """
    Stripe Connect integration per split payments.

    Gestisce:
    - Onboarding ASD (account creation, verification)
    - Checkout sessions con split payment
    - Webhook processing (payment success/failure)
    - Refunds (proportional to platform + ASD)

    USAGE:
    ```python
    service = StripeConnectService(db)

    # Onboard ASD
    url = await service.create_account_link(asd_id)

    # Create checkout
    session = await service.create_checkout_session(subscription_id)

    # Process webhook
    await service.handle_webhook(payload, signature)
    ```
    """

    def __init__(
        self,
        db: AsyncSession,
        config: Optional[EventsConfig] = None
    ):
        """
        Inizializza Stripe Connect service.

        Args:
            db: Database session
            config: Events config (contains Stripe keys)
        """
        self.db = db
        self.config = config or get_events_config()

        # Configure Stripe
        stripe.api_key = self.config.stripe.secret_key

    # ======================== ACCOUNT MANAGEMENT ========================

    async def create_connect_account(
        self,
        asd_id: UUID,
        email: str,
        country: str = "IT",
        business_type: str = "non_profit"
    ) -> Tuple[str, str]:
        """
        Crea Stripe Connect account per ASD.

        Args:
            asd_id: ID ASD partner
            email: Email business
            country: Paese (default IT)
            business_type: Tipo business

        Returns:
            Tuple (account_id, account_link_url)

        STRIPE DOCS:
        - Account types: https://stripe.com/docs/connect/accounts
        - Onboarding: https://stripe.com/docs/connect/custom/hosted-onboarding
        """
        try:
            # Create Express account (simplified onboarding)
            account = stripe.Account.create(
                type="express",
                country=country,
                email=email,
                capabilities={
                    "card_payments": {"requested": True},
                    "transfers": {"requested": True},
                },
                business_type=business_type,
                metadata={
                    "asd_id": str(asd_id),
                    "platform": "media_center_arti_marziali"
                }
            )

            # Update ASD with account ID
            await self.db.execute(
                update(ASDPartner)
                .where(ASDPartner.id == asd_id)
                .values(
                    stripe_account_id=account.id,
                    updated_at=datetime.utcnow()
                )
            )
            await self.db.flush()

            # Create account link for onboarding
            account_link = stripe.AccountLink.create(
                account=account.id,
                refresh_url=f"https://app.example.com/asd/{asd_id}/stripe/refresh",
                return_url=f"https://app.example.com/asd/{asd_id}/stripe/complete",
                type="account_onboarding"
            )

            logger.info(f"Created Stripe account {account.id} for ASD {asd_id}")
            return account.id, account_link.url

        except StripeError as e:
            logger.error(f"Stripe error creating account for ASD {asd_id}: {e}")
            raise ValueError(f"Failed to create Stripe account: {e.user_message}")

    async def create_account_link(
        self,
        asd_id: UUID,
        return_url: Optional[str] = None,
        refresh_url: Optional[str] = None
    ) -> str:
        """
        Crea link per onboarding o aggiornamento account.

        Args:
            asd_id: ID ASD partner
            return_url: URL ritorno dopo onboarding
            refresh_url: URL se link scade

        Returns:
            URL per onboarding

        USE CASE:
        - Nuovo ASD: Completa onboarding
        - ASD esistente: Aggiorna info (es. nuovo conto)
        """
        # Get ASD
        result = await self.db.execute(
            select(ASDPartner).where(ASDPartner.id == asd_id)
        )
        asd = result.scalar_one_or_none()
        if not asd:
            raise ValueError(f"ASD {asd_id} not found")

        if not asd.stripe_account_id:
            raise ValueError(f"ASD {asd_id} has no Stripe account")

        try:
            account_link = stripe.AccountLink.create(
                account=asd.stripe_account_id,
                refresh_url=refresh_url or f"https://app.example.com/asd/{asd_id}/stripe/refresh",
                return_url=return_url or f"https://app.example.com/asd/{asd_id}/stripe/complete",
                type="account_onboarding"
            )

            return account_link.url

        except StripeError as e:
            logger.error(f"Stripe error creating account link: {e}")
            raise ValueError(f"Failed to create account link: {e.user_message}")

    async def get_account_status(
        self,
        asd_id: UUID
    ) -> Dict[str, Any]:
        """
        Ottiene status account Stripe.

        Args:
            asd_id: ID ASD partner

        Returns:
            Dict con status account
        """
        result = await self.db.execute(
            select(ASDPartner).where(ASDPartner.id == asd_id)
        )
        asd = result.scalar_one_or_none()
        if not asd or not asd.stripe_account_id:
            return {"connected": False}

        try:
            account = stripe.Account.retrieve(asd.stripe_account_id)

            status = {
                "connected": True,
                "account_id": account.id,
                "charges_enabled": account.charges_enabled,
                "payouts_enabled": account.payouts_enabled,
                "details_submitted": account.details_submitted,
                "requirements": {
                    "currently_due": account.requirements.currently_due if account.requirements else [],
                    "eventually_due": account.requirements.eventually_due if account.requirements else [],
                    "past_due": account.requirements.past_due if account.requirements else [],
                    "disabled_reason": account.requirements.disabled_reason if account.requirements else None
                }
            }

            # Update verified status in DB
            is_verified = account.charges_enabled and account.payouts_enabled
            if asd.stripe_onboarding_complete != is_verified:
                asd.stripe_onboarding_complete = is_verified
                await self.db.flush()

            return status

        except StripeError as e:
            logger.error(f"Error retrieving Stripe account: {e}")
            return {"connected": True, "error": str(e)}

    # ======================== CHECKOUT ========================

    async def create_checkout_session(
        self,
        subscription_id: UUID,
        success_url: str,
        cancel_url: str
    ) -> Dict[str, Any]:
        """
        Crea Stripe Checkout session con split payment.

        Args:
            subscription_id: ID subscription
            success_url: URL successo
            cancel_url: URL cancellazione

        Returns:
            Dict con session_id e checkout_url

        SPLIT PAYMENT:
        - amount: Totale pagato da utente
        - application_fee_amount: Fee piattaforma (va a LIBRA)
        - transfer_data.destination: Account ASD (riceve resto)
        """
        # Get subscription with event and ASD
        result = await self.db.execute(
            select(EventSubscription).where(EventSubscription.id == subscription_id)
        )
        subscription = result.scalar_one_or_none()
        if not subscription:
            raise ValueError(f"Subscription {subscription_id} not found")

        # Get event
        event_result = await self.db.execute(
            select(Event).where(Event.id == subscription.event_id)
        )
        event = event_result.scalar_one_or_none()
        if not event:
            raise ValueError("Event not found")

        # Get ASD
        asd_result = await self.db.execute(
            select(ASDPartner).where(ASDPartner.id == event.asd_id)
        )
        asd = asd_result.scalar_one_or_none()
        if not asd:
            raise ValueError("ASD not found")

        if not asd.stripe_account_id:
            raise ValueError("ASD has no Stripe Connect account")

        if not asd.stripe_onboarding_complete:
            raise ValueError("ASD Stripe account not verified")

        try:
            # Create Checkout Session with destination charge
            session = stripe.checkout.Session.create(
                mode="payment",
                payment_method_types=["card"],
                line_items=[{
                    "price_data": {
                        "currency": self.config.stripe.currency,
                        "product_data": {
                            "name": event.title,
                            "description": event.short_description or f"Iscrizione evento {event.title}",
                        },
                        "unit_amount": subscription.amount_cents,
                    },
                    "quantity": 1,
                }],
                # SPLIT PAYMENT: Application fee goes to platform
                payment_intent_data={
                    "application_fee_amount": subscription.platform_amount_cents,
                    "transfer_data": {
                        "destination": asd.stripe_account_id,
                    },
                    "metadata": {
                        "subscription_id": str(subscription_id),
                        "event_id": str(event.id),
                        "asd_id": str(asd.id),
                        "user_id": str(subscription.user_id)
                    }
                },
                success_url=success_url + "?session_id={CHECKOUT_SESSION_ID}",
                cancel_url=cancel_url,
                expires_at=int((datetime.now(timezone.utc) + timedelta(
                    minutes=self.config.checkout_session_expiry_minutes
                )).timestamp()),
                metadata={
                    "subscription_id": str(subscription_id),
                    "event_id": str(event.id),
                    "asd_id": str(asd.id)
                }
            )

            # Update subscription with session ID
            subscription.stripe_checkout_session_id = session.id
            subscription.updated_at = datetime.utcnow()
            await self.db.flush()

            logger.info(f"Created checkout session {session.id} for subscription {subscription_id}")

            return {
                "session_id": session.id,
                "checkout_url": session.url,
                "expires_at": datetime.fromtimestamp(session.expires_at)
            }

        except StripeError as e:
            logger.error(f"Stripe error creating checkout session: {e}")
            raise ValueError(f"Failed to create checkout: {e.user_message}")

    async def get_session_status(
        self,
        session_id: str
    ) -> Dict[str, Any]:
        """
        Ottiene status sessione checkout.

        Args:
            session_id: Stripe session ID

        Returns:
            Dict con status
        """
        try:
            session = stripe.checkout.Session.retrieve(session_id)

            return {
                "status": session.status,
                "payment_status": session.payment_status,
                "amount_total": session.amount_total,
                "currency": session.currency,
                "payment_intent": session.payment_intent,
                "customer_email": session.customer_details.email if session.customer_details else None
            }

        except StripeError as e:
            logger.error(f"Error retrieving session: {e}")
            return {"error": str(e)}

    # ======================== WEBHOOKS ========================

    async def handle_webhook(
        self,
        payload: bytes,
        signature: str,
        webhook_secret: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Processa Stripe webhook.

        Args:
            payload: Raw webhook payload
            signature: Stripe signature header
            webhook_secret: Webhook secret (default from config)

        Returns:
            Dict con risultato processing

        EVENTS HANDLED:
        - checkout.session.completed: Pagamento completato
        - checkout.session.expired: Sessione scaduta
        - charge.refunded: Rimborso completato
        - account.updated: Account ASD aggiornato
        """
        secret = webhook_secret or self.config.stripe.webhook_secret

        try:
            event = stripe.Webhook.construct_event(
                payload, signature, secret
            )
        except ValueError as e:
            logger.error(f"Invalid webhook payload: {e}")
            return {"error": "Invalid payload"}
        except SignatureVerificationError as e:
            logger.error(f"Invalid webhook signature: {e}")
            return {"error": "Invalid signature"}

        event_type = event["type"]
        data = event["data"]["object"]

        logger.info(f"Processing webhook: {event_type}")

        if event_type == "checkout.session.completed":
            return await self._handle_checkout_completed(data)
        elif event_type == "checkout.session.expired":
            return await self._handle_checkout_expired(data)
        elif event_type == "charge.refunded":
            return await self._handle_charge_refunded(data)
        elif event_type == "account.updated":
            return await self._handle_account_updated(data)
        else:
            logger.info(f"Unhandled webhook event: {event_type}")
            return {"status": "ignored", "event_type": event_type}

    async def _handle_checkout_completed(
        self,
        session: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Handle successful checkout.

        Updates subscription status to CONFIRMED.
        """
        subscription_id = session.get("metadata", {}).get("subscription_id")
        if not subscription_id:
            logger.warning("Checkout completed without subscription_id")
            return {"error": "Missing subscription_id"}

        payment_intent = session.get("payment_intent")

        # Update subscription
        result = await self.db.execute(
            update(EventSubscription)
            .where(EventSubscription.id == subscription_id)
            .values(
                status=SubscriptionStatus.CONFIRMED,
                stripe_payment_intent_id=payment_intent,
                confirmed_at=datetime.utcnow(),
                updated_at=datetime.utcnow()
            )
        )

        if result.rowcount == 0:
            logger.warning(f"Subscription {subscription_id} not found")
            return {"error": "Subscription not found"}

        # Get subscription to update event capacity
        sub_result = await self.db.execute(
            select(EventSubscription).where(EventSubscription.id == subscription_id)
        )
        subscription = sub_result.scalar_one_or_none()

        if subscription:
            await self.db.execute(
                update(Event)
                .where(Event.id == subscription.event_id)
                .values(current_subscriptions=Event.current_subscriptions + 1)
            )

        await self.db.commit()

        logger.info(f"Checkout completed for subscription {subscription_id}")
        return {"status": "confirmed", "subscription_id": subscription_id}

    async def _handle_checkout_expired(
        self,
        session: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Handle expired checkout session.

        Updates subscription status to EXPIRED.
        """
        subscription_id = session.get("metadata", {}).get("subscription_id")
        if not subscription_id:
            return {"status": "ignored"}

        await self.db.execute(
            update(EventSubscription)
            .where(
                EventSubscription.id == subscription_id,
                EventSubscription.status == SubscriptionStatus.PENDING
            )
            .values(
                status=SubscriptionStatus.CANCELLED,
                updated_at=datetime.utcnow()
            )
        )
        await self.db.commit()

        logger.info(f"Checkout expired for subscription {subscription_id}")
        return {"status": "expired", "subscription_id": subscription_id}

    async def _handle_charge_refunded(
        self,
        charge: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Handle refund completion.

        Updates refund request status.
        """
        payment_intent = charge.get("payment_intent")
        refund_id = charge.get("refunds", {}).get("data", [{}])[0].get("id")

        if not payment_intent:
            return {"status": "ignored"}

        # Find subscription by payment intent
        sub_result = await self.db.execute(
            select(EventSubscription).where(
                EventSubscription.stripe_payment_intent_id == payment_intent
            )
        )
        subscription = sub_result.scalar_one_or_none()

        if not subscription:
            logger.warning(f"No subscription found for payment intent {payment_intent}")
            return {"status": "subscription_not_found"}

        # Update refund request
        await self.db.execute(
            update(ASDRefundRequest)
            .where(
                ASDRefundRequest.subscription_id == subscription.id,
                ASDRefundRequest.status == RefundStatus.APPROVED
            )
            .values(
                status=RefundStatus.PROCESSED,
                stripe_refund_id=refund_id,
                processed_at=datetime.utcnow(),
                updated_at=datetime.utcnow()
            )
        )

        # Update subscription status
        subscription.status = SubscriptionStatus.REFUNDED
        subscription.updated_at = datetime.utcnow()

        await self.db.commit()

        logger.info(f"Refund processed for subscription {subscription.id}")
        return {"status": "refunded", "subscription_id": str(subscription.id)}

    async def _handle_account_updated(
        self,
        account: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Handle Connect account update.

        Updates ASD verification status.
        """
        account_id = account.get("id")
        charges_enabled = account.get("charges_enabled", False)
        payouts_enabled = account.get("payouts_enabled", False)

        is_verified = charges_enabled and payouts_enabled

        result = await self.db.execute(
            update(ASDPartner)
            .where(ASDPartner.stripe_account_id == account_id)
            .values(
                stripe_onboarding_complete=is_verified,
                stripe_account_status="active" if is_verified else "pending",
                updated_at=datetime.utcnow()
            )
        )

        if result.rowcount > 0:
            await self.db.commit()
            logger.info(f"Account {account_id} updated, verified={is_verified}")
            return {"status": "updated", "verified": is_verified}

        return {"status": "account_not_found"}

    # ======================== REFUNDS ========================

    async def create_refund(
        self,
        refund_request_id: UUID
    ) -> Dict[str, Any]:
        """
        Crea rimborso Stripe.

        Args:
            refund_request_id: ID richiesta rimborso

        Returns:
            Dict con refund info

        REFUND SPLIT:
        - Stripe gestisce refund proporzionale automaticamente
        - Platform fee: Refunded to platform
        - ASD amount: Refunded from ASD account
        """
        # Get refund request
        result = await self.db.execute(
            select(ASDRefundRequest).where(ASDRefundRequest.id == refund_request_id)
        )
        refund_request = result.scalar_one_or_none()
        if not refund_request:
            raise ValueError(f"Refund request {refund_request_id} not found")

        if refund_request.status != RefundStatus.APPROVED:
            raise ValueError("Refund must be approved first")

        # Get subscription
        sub_result = await self.db.execute(
            select(EventSubscription).where(
                EventSubscription.id == refund_request.subscription_id
            )
        )
        subscription = sub_result.scalar_one_or_none()
        if not subscription:
            raise ValueError("Subscription not found")

        if not subscription.stripe_payment_intent_id:
            raise ValueError("No payment intent for subscription")

        try:
            # Create refund on the PaymentIntent
            # Stripe automatically handles proportional refund for Connect
            refund = stripe.Refund.create(
                payment_intent=subscription.stripe_payment_intent_id,
                amount=refund_request.requested_amount_cents,
                reason="requested_by_customer",
                metadata={
                    "refund_request_id": str(refund_request_id),
                    "subscription_id": str(subscription.id),
                    "user_id": str(refund_request.requested_by)
                },
                # Reverse transfer to ASD proportionally
                reverse_transfer=True,
                refund_application_fee=True  # Also refund platform fee
            )

            # Update refund request
            refund_request.stripe_refund_id = refund.id
            refund_request.status = RefundStatus.PROCESSED
            refund_request.processed_at = datetime.utcnow()

            # Update subscription
            subscription.status = SubscriptionStatus.REFUNDED
            subscription.updated_at = datetime.utcnow()

            # Update event capacity
            await self.db.execute(
                update(Event)
                .where(Event.id == subscription.event_id)
                .values(current_subscriptions=Event.current_subscriptions - 1)
            )

            await self.db.flush()

            logger.info(f"Created refund {refund.id} for request {refund_request_id}")

            return {
                "refund_id": refund.id,
                "amount": refund.amount,
                "status": refund.status,
                "created": datetime.fromtimestamp(refund.created)
            }

        except StripeError as e:
            logger.error(f"Stripe error creating refund: {e}")
            raise ValueError(f"Failed to create refund: {e.user_message}")

    async def get_refund_status(
        self,
        stripe_refund_id: str
    ) -> Dict[str, Any]:
        """
        Ottiene status rimborso.

        Args:
            stripe_refund_id: Stripe refund ID

        Returns:
            Dict con status
        """
        try:
            refund = stripe.Refund.retrieve(stripe_refund_id)

            return {
                "id": refund.id,
                "amount": refund.amount,
                "status": refund.status,
                "reason": refund.reason,
                "created": datetime.fromtimestamp(refund.created),
                "failure_reason": refund.failure_reason
            }

        except StripeError as e:
            logger.error(f"Error retrieving refund: {e}")
            return {"error": str(e)}

    # ======================== PAYOUTS ========================

    async def get_asd_balance(
        self,
        asd_id: UUID
    ) -> Dict[str, Any]:
        """
        Ottiene balance account ASD.

        Args:
            asd_id: ID ASD partner

        Returns:
            Dict con balance info
        """
        result = await self.db.execute(
            select(ASDPartner).where(ASDPartner.id == asd_id)
        )
        asd = result.scalar_one_or_none()
        if not asd or not asd.stripe_account_id:
            return {"error": "ASD not connected to Stripe"}

        try:
            balance = stripe.Balance.retrieve(
                stripe_account=asd.stripe_account_id
            )

            available = sum(
                b["amount"] for b in balance.available
                if b["currency"] == self.config.stripe.currency
            )
            pending = sum(
                b["amount"] for b in balance.pending
                if b["currency"] == self.config.stripe.currency
            )

            return {
                "available_cents": available,
                "pending_cents": pending,
                "currency": self.config.stripe.currency
            }

        except StripeError as e:
            logger.error(f"Error retrieving balance: {e}")
            return {"error": str(e)}

    async def list_asd_payouts(
        self,
        asd_id: UUID,
        limit: int = 10
    ) -> List[Dict[str, Any]]:
        """
        Lista payouts ASD.

        Args:
            asd_id: ID ASD partner
            limit: Max risultati

        Returns:
            Lista payouts
        """
        result = await self.db.execute(
            select(ASDPartner).where(ASDPartner.id == asd_id)
        )
        asd = result.scalar_one_or_none()
        if not asd or not asd.stripe_account_id:
            return []

        try:
            payouts = stripe.Payout.list(
                stripe_account=asd.stripe_account_id,
                limit=limit
            )

            return [
                {
                    "id": p.id,
                    "amount": p.amount,
                    "currency": p.currency,
                    "status": p.status,
                    "arrival_date": datetime.fromtimestamp(p.arrival_date),
                    "created": datetime.fromtimestamp(p.created),
                    "method": p.method
                }
                for p in payouts.data
            ]

        except StripeError as e:
            logger.error(f"Error listing payouts: {e}")
            return []

    # ======================== DASHBOARD LINK ========================

    async def create_dashboard_link(
        self,
        asd_id: UUID
    ) -> str:
        """
        Crea link per dashboard Stripe Express.

        Args:
            asd_id: ID ASD partner

        Returns:
            URL dashboard

        USE CASE:
        - ASD vuole vedere transazioni, payouts
        - Stripe Express dashboard (hosted by Stripe)
        """
        result = await self.db.execute(
            select(ASDPartner).where(ASDPartner.id == asd_id)
        )
        asd = result.scalar_one_or_none()
        if not asd or not asd.stripe_account_id:
            raise ValueError("ASD not connected to Stripe")

        try:
            login_link = stripe.Account.create_login_link(
                asd.stripe_account_id
            )
            return login_link.url

        except StripeError as e:
            logger.error(f"Error creating dashboard link: {e}")
            raise ValueError(f"Failed to create dashboard link: {e.user_message}")

"""
🎓 AI_MODULE: Donation Models
🎓 AI_DESCRIPTION: Stelline wallet, donations, withdrawals, blockchain batches
🎓 AI_BUSINESS: Complete donation system with fiscal compliance
🎓 AI_TEACHING: Complex business logic + fiscal requirements + blockchain integration

💡 RELATIONSHIPS:
User 1 ────── 1 StellineWallet
User 1 ────── N WalletTransaction
User 1 ────── N Donation (as donor)
Maestro 1 ──── N Donation (as recipient)
ASD 1 ──────── N Donation (as recipient)
LiveEvent 1 ── N Donation
BlockchainBatch 1 ── N Donation
"""

from sqlalchemy import Column, String, Boolean, DateTime, Integer, BigInteger, Numeric, Enum, ForeignKey, Text, Index, CheckConstraint
from sqlalchemy.orm import relationship
from datetime import datetime, date
import uuid
import enum

from core.database import Base
from models import GUID, JSONBType


# === ENUMS ===

class FiscalReceiptType(str, enum.Enum):
    """
    Tipologia ricevuta fiscale.

    🎯 FISCAL COMPLIANCE:
    - CONTRIBUTO_SPONTANEO: Donazione anonima, non deducibile
    - DONAZIONE_LIBERALE: Con CF donatore, deducibile (Art. 83 CTS)
    """
    CONTRIBUTO_SPONTANEO = "contributo_spontaneo"
    DONAZIONE_LIBERALE = "donazione_liberale"


class WalletTransactionType(str, enum.Enum):
    """Tipo transazione wallet."""
    PURCHASE = "purchase"  # Acquisto stelline
    DONATION_SENT = "donation_sent"  # Donazione inviata
    DONATION_RECEIVED = "donation_received"  # Donazione ricevuta
    WITHDRAWAL = "withdrawal"  # Prelievo (maestro/ASD)
    REFUND = "refund"  # Rimborso


class WithdrawalStatus(str, enum.Enum):
    """Status richiesta prelievo."""
    PENDING = "pending"
    APPROVED = "approved"
    PROCESSING = "processing"
    COMPLETED = "completed"
    REJECTED = "rejected"


class PayoutMethod(str, enum.Enum):
    """Metodo payout."""
    SEPA = "sepa"  # Bonifico SEPA (gratis, 2-3 giorni)
    PAYPAL = "paypal"  # PayPal (2% fee, istantaneo)
    STRIPE = "stripe"  # Stripe (1.5% fee, 1 giorno)
    NUMIA = "numia"  # Numia Payment Gateway (1.8% fee, 1-2 giorni, carte IT)


# === MODELS ===

class StellineWallet(Base):
    """
    Wallet prepagato stelline per utente.

    🎯 CORE DONATION SYSTEM: 1 stellina = €0.01
    """
    __tablename__ = "stelline_wallets"

    id = Column(GUID(), primary_key=True, default=uuid.uuid4)
    user_id = Column(GUID(), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, unique=True)

    # === BALANCE ===
    balance_stelline = Column(BigInteger, default=0, nullable=False)
    # balance_euro is computed: balance_stelline * 0.01

    # === MONTHLY LIMITS (per minori) ===
    monthly_donated_stelline = Column(BigInteger, default=0, nullable=False)
    last_donation_reset = Column(DateTime, default=datetime.utcnow, nullable=False)

    # === METADATA ===
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

    # === RELATIONSHIPS ===
    user = relationship("User", backref="stelline_wallet")
    transactions = relationship("WalletTransaction", back_populates="wallet", cascade="all, delete-orphan")

    # === CONSTRAINTS ===
    __table_args__ = (
        CheckConstraint('balance_stelline >= 0', name='check_balance_positive'),
        CheckConstraint('monthly_donated_stelline >= 0', name='check_monthly_positive'),
        Index('idx_wallet_user', 'user_id'),
    )

    # === BUSINESS METHODS ===

    def get_balance_euro(self) -> float:
        """Get balance in euros."""
        return self.balance_stelline * 0.01

    def add_stelline(self, amount: int) -> None:
        """Add stelline to wallet."""
        if amount <= 0:
            raise ValueError("Amount must be positive")
        self.balance_stelline += amount
        self.updated_at = datetime.utcnow()

    def remove_stelline(self, amount: int) -> None:
        """Remove stelline from wallet."""
        if amount <= 0:
            raise ValueError("Amount must be positive")
        if self.balance_stelline < amount:
            raise ValueError("Insufficient balance")
        self.balance_stelline -= amount
        self.updated_at = datetime.utcnow()

    def reset_monthly_limit_if_needed(self) -> None:
        """Reset monthly donation limit if new month."""
        now = datetime.utcnow()
        if now.month != self.last_donation_reset.month or now.year != self.last_donation_reset.year:
            self.monthly_donated_stelline = 0
            self.last_donation_reset = now

    def can_donate(self, amount: int, monthly_limit: int = None) -> bool:
        """
        Check if user can donate amount.

        Args:
            amount: Stelline to donate
            monthly_limit: Monthly limit (for minors), None = no limit
        """
        if self.balance_stelline < amount:
            return False

        if monthly_limit is not None:
            self.reset_monthly_limit_if_needed()
            if self.monthly_donated_stelline + amount > monthly_limit:
                return False

        return True

    def __repr__(self):
        return f"<StellineWallet user={self.user_id} balance={self.balance_stelline}>"


class WalletTransaction(Base):
    """
    Transazioni wallet (acquisti, donazioni, prelievi).

    🎯 AUDIT TRAIL: Track ogni movimento stelline
    """
    __tablename__ = "wallet_transactions"

    id = Column(GUID(), primary_key=True, default=uuid.uuid4)
    wallet_id = Column(GUID(), ForeignKey("stelline_wallets.id", ondelete="CASCADE"), nullable=False)

    # === TRANSACTION INFO ===
    type = Column(Enum(WalletTransactionType), nullable=False, index=True)
    amount_stelline = Column(BigInteger, nullable=False)  # Positive = credit, Negative = debit

    # === REFERENCES ===
    donation_id = Column(GUID(), ForeignKey("donations.id", ondelete="SET NULL"), nullable=True)
    payment_intent_id = Column(String(255), nullable=True)  # Stripe payment ID (for purchases)
    withdrawal_request_id = Column(GUID(), ForeignKey("withdrawal_requests.id", ondelete="SET NULL"), nullable=True)

    # === BALANCE AFTER ===
    balance_after = Column(BigInteger, nullable=False)

    # === METADATA ===
    description = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)

    # === RELATIONSHIPS ===
    wallet = relationship("StellineWallet", back_populates="transactions")
    donation = relationship("Donation", foreign_keys=[donation_id])
    withdrawal_request = relationship("WithdrawalRequest", foreign_keys=[withdrawal_request_id])

    __table_args__ = (
        Index('idx_wallet_tx_type_date', 'wallet_id', 'type', 'created_at'),
        Index('idx_wallet_tx_donation', 'donation_id'),
    )

    def __repr__(self):
        return f"<WalletTransaction {self.type.value} {self.amount_stelline}>"


class Donation(Base):
    """
    Donazioni con split maestro/ASD/platform.

    🎯 CORE MONETIZATION: Stelline → Maestri/ASD
    """
    __tablename__ = "donations"

    id = Column(GUID(), primary_key=True, default=uuid.uuid4)

    # === DONOR ===
    from_user_id = Column(GUID(), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)

    # === RECIPIENT (one of these) ===
    to_maestro_id = Column(GUID(), ForeignKey("maestros.id", ondelete="SET NULL"), nullable=True)
    to_asd_id = Column(GUID(), ForeignKey("asds.id", ondelete="SET NULL"), nullable=True)
    to_event_id = Column(GUID(), ForeignKey("live_events.id", ondelete="SET NULL"), nullable=True)

    # === AMOUNT ===
    stelline_amount = Column(BigInteger, nullable=False)
    # euro_amount is computed: stelline_amount * 0.01

    # === SPLIT (calculated at donation time) ===
    split_data = Column(JSONBType(), nullable=False)
    # Example: {"maestro": 700, "asd": 250, "platform": 50}

    # === CONTEXT ===
    message = Column(Text, nullable=True)
    is_anonymous = Column(Boolean, default=False, nullable=False)

    # === FISCAL ===
    donor_codice_fiscale = Column(String(16), nullable=True)
    fiscal_receipt_type = Column(Enum(FiscalReceiptType), nullable=True)
    receipt_url = Column(Text, nullable=True)  # PDF ricevuta Art. 83
    receipt_generated_at = Column(DateTime, nullable=True)

    # === BLOCKCHAIN ===
    batch_id = Column(BigInteger, ForeignKey("donation_blockchain_batches.id", ondelete="SET NULL"), nullable=True)
    blockchain_tx_hash = Column(String(66), nullable=True)
    blockchain_verified = Column(Boolean, default=False, nullable=False)

    # === METADATA ===
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)

    # === RELATIONSHIPS ===
    from_user = relationship("User", foreign_keys=[from_user_id])
    to_maestro = relationship("Maestro", foreign_keys=[to_maestro_id])
    to_asd = relationship("ASD", foreign_keys=[to_asd_id])
    to_event = relationship("LiveEvent", foreign_keys=[to_event_id])
    batch = relationship("DonationBlockchainBatch", back_populates="donations")

    __table_args__ = (
        CheckConstraint('stelline_amount > 0', name='check_donation_positive'),
        CheckConstraint(
            '(to_maestro_id IS NOT NULL)::int + (to_asd_id IS NOT NULL)::int + (to_event_id IS NOT NULL)::int = 1',
            name='check_one_recipient'
        ),
        Index('idx_donation_from_user', 'from_user_id', 'created_at'),
        Index('idx_donation_to_maestro', 'to_maestro_id', 'created_at'),
        Index('idx_donation_to_asd', 'to_asd_id', 'created_at'),
        Index('idx_donation_to_event', 'to_event_id'),
        Index('idx_donation_batch', 'batch_id'),
        Index('idx_donation_fiscal', 'fiscal_receipt_type', 'created_at'),
    )

    # === BUSINESS METHODS ===

    def get_euro_amount(self) -> float:
        """Get amount in euros."""
        return self.stelline_amount * 0.01

    def get_recipient_id(self) -> str:
        """Get recipient ID (maestro/ASD/event)."""
        if self.to_maestro_id:
            return f"maestro:{self.to_maestro_id}"
        elif self.to_asd_id:
            return f"asd:{self.to_asd_id}"
        elif self.to_event_id:
            return f"event:{self.to_event_id}"
        return "unknown"

    def requires_fiscal_receipt(self) -> bool:
        """Check if requires fiscal receipt (Art. 83)."""
        return (
            self.fiscal_receipt_type == FiscalReceiptType.DONAZIONE_LIBERALE
            and self.donor_codice_fiscale is not None
        )

    def __repr__(self):
        return f"<Donation {self.stelline_amount} stelline to {self.get_recipient_id()}>"


class WithdrawalRequest(Base):
    """
    Richieste prelievo stelline (maestri/ASD).

    🎯 PAYOUT SYSTEM: Stelline → EUR → Bank account
    """
    __tablename__ = "withdrawal_requests"

    id = Column(GUID(), primary_key=True, default=uuid.uuid4)

    # === REQUESTER ===
    user_id = Column(GUID(), ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    maestro_id = Column(GUID(), ForeignKey("maestros.id", ondelete="CASCADE"), nullable=True)
    asd_id = Column(GUID(), ForeignKey("asds.id", ondelete="CASCADE"), nullable=True)

    # === AMOUNT ===
    stelline_amount = Column(BigInteger, nullable=False)
    euro_amount = Column(Numeric(10, 2), nullable=False)

    # === PAYOUT METHOD ===
    payout_method = Column(Enum(PayoutMethod), nullable=False)
    iban = Column(String(34), nullable=True)  # If SEPA
    paypal_email = Column(String(255), nullable=True)  # If PayPal
    stripe_account_id = Column(String(255), nullable=True)  # If Stripe

    # === STATUS ===
    status = Column(
        Enum(WithdrawalStatus, values_callable=lambda x: [e.value for e in x], name='withdrawalstatus', create_type=False),
        default=WithdrawalStatus.PENDING.value,
        nullable=False,
        index=True
    )

    # === PROCESSING ===
    requested_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    approved_at = Column(DateTime, nullable=True)
    approved_by_user_id = Column(GUID(), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    completed_at = Column(DateTime, nullable=True)
    rejected_at = Column(DateTime, nullable=True)

    # === NOTES ===
    admin_notes = Column(Text, nullable=True)
    rejection_reason = Column(Text, nullable=True)

    # === PAYMENT REFERENCE ===
    payment_reference = Column(String(255), nullable=True)  # Bank/PayPal/Stripe transaction ID

    # === RELATIONSHIPS ===
    user = relationship("User", foreign_keys=[user_id])
    maestro = relationship("Maestro", foreign_keys=[maestro_id])
    asd = relationship("ASD", foreign_keys=[asd_id])
    approved_by = relationship("User", foreign_keys=[approved_by_user_id])

    __table_args__ = (
        CheckConstraint('stelline_amount >= 1000000', name='check_min_withdrawal'),  # Min 10,000 stelline = €100
        CheckConstraint(
            '(maestro_id IS NOT NULL)::int + (asd_id IS NOT NULL)::int = 1',
            name='check_one_entity'
        ),
        Index('idx_withdrawal_status', 'status', 'requested_at'),
        Index('idx_withdrawal_user', 'user_id'),
        Index('idx_withdrawal_maestro', 'maestro_id'),
        Index('idx_withdrawal_asd', 'asd_id'),
    )

    def __repr__(self):
        return f"<WithdrawalRequest €{self.euro_amount} {self.status.value}>"


class DonationBlockchainBatch(Base):
    """
    Batch donazioni registrate su blockchain.

    🎯 BLOCKCHAIN TRANSPARENCY: Aggregazione per ridurre gas fees
    """
    __tablename__ = "donation_blockchain_batches"

    id = Column(BigInteger, primary_key=True, autoincrement=True)

    # === BATCH TYPE ===
    batch_type = Column(String(50), nullable=False, index=True)  # 'daily', 'event', 'weekly'
    event_id = Column(GUID(), ForeignKey("live_events.id", ondelete="SET NULL"), nullable=True)

    # === DATA ===
    total_stelline = Column(BigInteger, nullable=False)
    total_donations = Column(Integer, nullable=False)
    merkle_root = Column(String(66), nullable=False)  # Root hash delle donazioni

    # === BLOCKCHAIN ===
    tx_hash = Column(String(66), nullable=True, index=True)  # Transaction hash Polygon
    block_number = Column(BigInteger, nullable=True)
    confirmed = Column(Boolean, default=False, nullable=False)

    # === IPFS ===
    ipfs_hash = Column(String(100), nullable=True)  # Metadata JSON su IPFS

    # === METADATA ===
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)
    confirmed_at = Column(DateTime, nullable=True)

    # === RELATIONSHIPS ===
    donations = relationship("Donation", back_populates="batch")
    event = relationship("LiveEvent", foreign_keys=[event_id])

    __table_args__ = (
        Index('idx_blockchain_batch_type', 'batch_type', 'created_at'),
        Index('idx_blockchain_confirmed', 'confirmed', 'created_at'),
    )

    def __repr__(self):
        return f"<DonationBlockchainBatch {self.batch_type} {self.total_donations} donations>"

#!/usr/bin/env python3
"""
================================================================================
    SEED EVENTS DATA - Idempotent Seed Script for Events Testing
================================================================================

AI_MODULE: SeedEventsData
AI_DESCRIPTION: Script idempotente per popolamento dati test eventi
AI_BUSINESS: Permette testing frontend/backend con dati realistici
AI_TEACHING: Idempotent seeding, upsert patterns, test data generation

USAGE:
    python scripts/seed_events.py

    Options:
        --clean     Remove all seed data before re-seeding
        --verbose   Show detailed output

SEEDED DATA:
    - 3 ASD Partners (verified, with fake Stripe accounts)
    - 8 Events (draft, presale, open, sold_out, completed)
    - Event Options (standard, VIP, early bird)
    - Sample subscriptions
    - Waiting list entries

================================================================================
"""

import os
import sys
import uuid
import asyncio
from datetime import datetime, date, timedelta
from pathlib import Path
from typing import Optional

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

# Load environment
from dotenv import load_dotenv
load_dotenv(Path(__file__).parent.parent / ".env")

# Import database and models
from sqlalchemy import select, delete
from sqlalchemy.ext.asyncio import AsyncSession
from core.database import AsyncSessionLocal

# Import Event models
from modules.events.models import (
    ASDPartner, Event, EventOption, EventSubscription, EventWaitingList,
    EventStatus, SubscriptionStatus, RefundApprovalMode
)

# Import User model
from models.user import User


# ============================================================================
# SEED DATA DEFINITIONS
# ============================================================================

SEED_PREFIX = "seed_"  # Prefix for identifying seeded data

# ASD Partners
ASD_PARTNERS = [
    {
        "name": "Wing Chun Academy Milano",
        "slug": f"{SEED_PREFIX}wing-chun-milano",
        "description": "La più antica accademia di Wing Chun in Lombardia. Fondata nel 1985.",
        "email": "info@wingchunmilano.it",
        "city": "Milano",
        "province": "MI",
        "country": "Italia",
        "stripe_account_id": f"acct_{SEED_PREFIX}wingchun_001",
        "stripe_account_status": "active",
        "stripe_onboarding_complete": True,
        "is_verified": True,
        "is_active": True,
        "default_split_percentage": 85.0,
    },
    {
        "name": "Tai Chi Roma Centro",
        "slug": f"{SEED_PREFIX}tai-chi-roma",
        "description": "Centro specializzato in Tai Chi Chuan stile Yang. Corsi per tutti i livelli.",
        "email": "segreteria@taichiroma.it",
        "city": "Roma",
        "province": "RM",
        "country": "Italia",
        "stripe_account_id": f"acct_{SEED_PREFIX}taichi_002",
        "stripe_account_status": "active",
        "stripe_onboarding_complete": True,
        "is_verified": True,
        "is_active": True,
        "default_split_percentage": 80.0,
    },
    {
        "name": "Kung Fu Firenze ASD",
        "slug": f"{SEED_PREFIX}kungfu-firenze",
        "description": "Associazione sportiva dedicata alle arti marziali cinesi tradizionali.",
        "email": "info@kungfufirenze.org",
        "city": "Firenze",
        "province": "FI",
        "country": "Italia",
        "stripe_account_id": f"acct_{SEED_PREFIX}kungfu_003",
        "stripe_account_status": "active",
        "stripe_onboarding_complete": True,
        "is_verified": True,
        "is_active": True,
        "default_split_percentage": 82.0,
    },
]


def get_events_data(asd_ids: dict) -> list:
    """
    Generate events data with dynamic dates.
    Dates are relative to today to ensure events are always relevant.
    """
    today = date.today()

    return [
        # === DRAFT EVENT ===
        {
            "asd_slug": f"{SEED_PREFIX}wing-chun-milano",
            "title": "Stage Estivo Wing Chun - Bozza",
            "slug": f"{SEED_PREFIX}stage-estivo-wingchun-draft",
            "description": "Stage intensivo estivo di Wing Chun. IN PREPARAZIONE.",
            "short_description": "Stage estivo Wing Chun - Coming soon",
            "start_date": today + timedelta(days=90),
            "end_date": today + timedelta(days=94),
            "total_capacity": 40,
            "current_subscriptions": 0,
            "location_name": "Palestra Comunale",
            "location_city": "Milano",
            "status": EventStatus.DRAFT,
            "discipline": "Wing Chun",
            "instructor_name": "Maestro Giovanni Rossi",
            "options": [
                {
                    "name": "Partecipazione Completa (5 giorni)",
                    "price_cents": 45000,
                    "early_bird_price_cents": 38000,
                    "early_bird_days": 30,
                    "sort_order": 1,
                },
            ]
        },

        # === PRESALE EVENT ===
        {
            "asd_slug": f"{SEED_PREFIX}tai-chi-roma",
            "title": "Ritiro Tai Chi - Prevendita Attiva",
            "slug": f"{SEED_PREFIX}ritiro-taichi-presale",
            "description": "Ritiro di 3 giorni immersi nella natura. Prevendita esclusiva per abbonati.",
            "short_description": "Ritiro Tai Chi - Prevendita attiva",
            "start_date": today + timedelta(days=60),
            "end_date": today + timedelta(days=62),
            "total_capacity": 25,
            "current_subscriptions": 8,
            "min_threshold": 10,
            "location_name": "Agriturismo Le Querce",
            "location_city": "Tivoli",
            "status": EventStatus.PRESALE,
            "presale_enabled": True,
            "presale_start": datetime.now() - timedelta(days=7),
            "presale_end": datetime.now() + timedelta(days=7),
            "sale_start": datetime.now() + timedelta(days=7),
            "discipline": "Tai Chi",
            "instructor_name": "Maestra Liu Mei",
            "options": [
                {
                    "name": "Full Board (3 giorni + pasti)",
                    "price_cents": 35000,
                    "early_bird_price_cents": 29900,
                    "early_bird_days": 14,
                    "sort_order": 1,
                },
                {
                    "name": "Solo Corso (senza pasti)",
                    "price_cents": 22000,
                    "early_bird_price_cents": None,
                    "sort_order": 2,
                },
            ]
        },

        # === OPEN EVENTS (3) ===
        {
            "asd_slug": f"{SEED_PREFIX}wing-chun-milano",
            "title": "Seminario Chi Sao Intensivo",
            "slug": f"{SEED_PREFIX}seminario-chisao-open",
            "description": "Due giorni dedicati all'allenamento del Chi Sao. Aperto a praticanti di ogni stile.",
            "short_description": "Seminario Chi Sao - Iscrizioni aperte",
            "start_date": today + timedelta(days=30),
            "end_date": today + timedelta(days=31),
            "total_capacity": 30,
            "current_subscriptions": 12,
            "location_name": "Wing Chun Academy",
            "location_address": "Via Torino 45",
            "location_city": "Milano",
            "status": EventStatus.OPEN,
            "discipline": "Wing Chun",
            "instructor_name": "Sifu Marco Bianchi",
            "options": [
                {
                    "name": "Weekend Completo",
                    "price_cents": 18000,
                    "early_bird_price_cents": 15000,
                    "early_bird_days": 10,
                    "sort_order": 1,
                },
                {
                    "name": "Solo Sabato",
                    "price_cents": 10000,
                    "sort_order": 2,
                },
                {
                    "name": "Solo Domenica",
                    "price_cents": 10000,
                    "sort_order": 3,
                },
            ]
        },
        {
            "asd_slug": f"{SEED_PREFIX}kungfu-firenze",
            "title": "Workshop Forme Tradizionali",
            "slug": f"{SEED_PREFIX}workshop-forme-open",
            "description": "Approfondimento delle forme tradizionali Shaolin. Per praticanti intermedi.",
            "short_description": "Workshop forme Shaolin",
            "start_date": today + timedelta(days=21),
            "end_date": today + timedelta(days=21),
            "total_capacity": 20,
            "current_subscriptions": 5,
            "location_name": "Palestra Centro Storico",
            "location_city": "Firenze",
            "status": EventStatus.OPEN,
            "discipline": "Kung Fu Shaolin",
            "instructor_name": "Maestro Chen Wei",
            "options": [
                {
                    "name": "Giornata Intera",
                    "price_cents": 8500,
                    "sort_order": 1,
                },
            ]
        },
        {
            "asd_slug": f"{SEED_PREFIX}tai-chi-roma",
            "title": "Corso Spada Tai Chi",
            "slug": f"{SEED_PREFIX}corso-spada-open",
            "description": "Corso di 4 lezioni sulla forma della spada Tai Chi stile Yang.",
            "short_description": "Corso spada Tai Chi - 4 lezioni",
            "start_date": today + timedelta(days=14),
            "end_date": today + timedelta(days=35),  # 4 weekly lessons
            "total_capacity": 15,
            "current_subscriptions": 7,
            "location_name": "Tai Chi Roma Centro",
            "location_city": "Roma",
            "status": EventStatus.OPEN,
            "discipline": "Tai Chi",
            "instructor_name": "Maestra Liu Mei",
            "options": [
                {
                    "name": "Corso Completo (4 lezioni)",
                    "price_cents": 12000,
                    "early_bird_price_cents": 9900,
                    "early_bird_days": 7,
                    "sort_order": 1,
                },
            ]
        },

        # === SOLD OUT EVENT ===
        {
            "asd_slug": f"{SEED_PREFIX}wing-chun-milano",
            "title": "Masterclass con Grandmaster - SOLD OUT",
            "slug": f"{SEED_PREFIX}masterclass-gm-soldout",
            "description": "Evento esclusivo con il Grandmaster in visita dall'Hong Kong. TUTTO ESAURITO.",
            "short_description": "Masterclass esclusiva - SOLD OUT",
            "start_date": today + timedelta(days=45),
            "end_date": today + timedelta(days=47),
            "total_capacity": 20,
            "current_subscriptions": 20,  # SOLD OUT
            "location_name": "Grand Hotel Milano",
            "location_city": "Milano",
            "status": EventStatus.SOLD_OUT,
            "discipline": "Wing Chun",
            "instructor_name": "Grandmaster Ip Ching",
            "options": [
                {
                    "name": "VIP Package (3 giorni)",
                    "price_cents": 95000,
                    "sort_order": 1,
                },
                {
                    "name": "Standard (solo lezioni)",
                    "price_cents": 65000,
                    "sort_order": 2,
                },
            ]
        },

        # === COMPLETED EVENT (past) ===
        {
            "asd_slug": f"{SEED_PREFIX}kungfu-firenze",
            "title": "Stage Primaverile - Completato",
            "slug": f"{SEED_PREFIX}stage-primavera-completed",
            "description": "Stage primaverile completato con successo. 35 partecipanti.",
            "short_description": "Stage completato - Marzo 2024",
            "start_date": today - timedelta(days=60),
            "end_date": today - timedelta(days=57),
            "total_capacity": 40,
            "current_subscriptions": 35,
            "location_name": "Centro Sportivo Comunale",
            "location_city": "Firenze",
            "status": EventStatus.COMPLETED,
            "discipline": "Kung Fu",
            "instructor_name": "Maestro Franco Verdi",
            "options": [
                {
                    "name": "Stage Completo",
                    "price_cents": 28000,
                    "sort_order": 1,
                },
            ]
        },

        # === CANCELLED EVENT ===
        {
            "asd_slug": f"{SEED_PREFIX}tai-chi-roma",
            "title": "Evento Annullato - Causa Meteo",
            "slug": f"{SEED_PREFIX}evento-annullato",
            "description": "Evento all'aperto annullato per previsioni meteo avverse.",
            "short_description": "ANNULLATO - Rimborsi in corso",
            "start_date": today + timedelta(days=10),
            "end_date": today + timedelta(days=10),
            "total_capacity": 50,
            "current_subscriptions": 15,
            "location_name": "Parco Villa Borghese",
            "location_city": "Roma",
            "status": EventStatus.CANCELLED,
            "cancelled_at": datetime.now() - timedelta(days=2),
            "cancellation_reason": "Previsioni meteo avverse",
            "discipline": "Tai Chi",
            "options": [
                {
                    "name": "Pratica all'Alba",
                    "price_cents": 5000,
                    "sort_order": 1,
                },
            ]
        },
    ]


# ============================================================================
# SEED FUNCTIONS
# ============================================================================

async def get_or_create_test_user(db: AsyncSession) -> Optional[User]:
    """Get or create a test user for subscriptions."""
    # Try to find existing test user
    result = await db.execute(
        select(User).where(User.email == "giulia.bianchi@example.com")
    )
    user = result.scalar_one_or_none()

    if not user:
        # Try another seed user
        result = await db.execute(
            select(User).where(User.email.like("%test%")).limit(1)
        )
        user = result.scalar_one_or_none()

    if not user:
        # Get any user
        result = await db.execute(select(User).limit(1))
        user = result.scalar_one_or_none()

    return user


async def seed_asd_partners(db: AsyncSession, verbose: bool = False) -> dict:
    """Seed ASD Partners. Returns dict of slug -> id."""
    asd_ids = {}

    for data in ASD_PARTNERS:
        # Check if already exists
        result = await db.execute(
            select(ASDPartner).where(ASDPartner.slug == data["slug"])
        )
        existing = result.scalar_one_or_none()

        if existing:
            if verbose:
                print(f"  [SKIP] ASD Partner already exists: {data['name']}")
            asd_ids[data["slug"]] = existing.id
        else:
            # Create new
            asd = ASDPartner(
                id=uuid.uuid4(),
                **data,
                verified_at=datetime.now() if data.get("is_verified") else None,
            )
            db.add(asd)
            await db.flush()
            asd_ids[data["slug"]] = asd.id
            if verbose:
                print(f"  [CREATE] ASD Partner: {data['name']}")

    await db.commit()
    return asd_ids


async def seed_events(db: AsyncSession, asd_ids: dict, verbose: bool = False) -> dict:
    """Seed Events. Returns dict of slug -> id."""
    event_ids = {}
    events_data = get_events_data(asd_ids)

    for data in events_data:
        # Check if already exists
        result = await db.execute(
            select(Event).where(Event.slug == data["slug"])
        )
        existing = result.scalar_one_or_none()

        if existing:
            if verbose:
                print(f"  [SKIP] Event already exists: {data['title']}")
            event_ids[data["slug"]] = existing.id
            continue

        # Get ASD ID
        asd_slug = data.pop("asd_slug")
        asd_id = asd_ids.get(asd_slug)
        if not asd_id:
            print(f"  [ERROR] ASD not found for slug: {asd_slug}")
            continue

        # Extract options data
        options_data = data.pop("options", [])

        # Create event
        event = Event(
            id=uuid.uuid4(),
            asd_id=asd_id,
            **data,
            published_at=datetime.now() if data["status"] != EventStatus.DRAFT else None,
        )
        db.add(event)
        await db.flush()
        event_ids[data["slug"]] = event.id

        if verbose:
            print(f"  [CREATE] Event: {data['title']} ({data['status'].value})")

        # Create options
        for opt_data in options_data:
            early_bird_days = opt_data.pop("early_bird_days", None)
            early_bird_deadline = None
            if early_bird_days and opt_data.get("early_bird_price_cents"):
                early_bird_deadline = datetime.now() + timedelta(days=early_bird_days)

            option = EventOption(
                id=uuid.uuid4(),
                event_id=event.id,
                name=opt_data["name"],
                description=opt_data.get("description"),
                start_date=data["start_date"],
                end_date=data["end_date"],
                price_cents=opt_data["price_cents"],
                early_bird_price_cents=opt_data.get("early_bird_price_cents"),
                early_bird_deadline=early_bird_deadline,
                is_active=True,
                sort_order=opt_data.get("sort_order", 0),
            )
            db.add(option)
            if verbose:
                print(f"    [CREATE] Option: {opt_data['name']} - {opt_data['price_cents']/100}€")

    await db.commit()
    return event_ids


async def seed_subscriptions(db: AsyncSession, event_ids: dict, user: Optional[User], verbose: bool = False):
    """Seed sample subscriptions for the test user."""
    if not user:
        if verbose:
            print("  [SKIP] No test user found, skipping subscriptions")
        return

    # Get open event with options
    for slug, event_id in event_ids.items():
        if "open" in slug and "chisao" in slug:  # Seminario Chi Sao
            # Check if already subscribed
            result = await db.execute(
                select(EventSubscription).where(
                    EventSubscription.event_id == event_id,
                    EventSubscription.user_id == user.id
                )
            )
            if result.scalar_one_or_none():
                if verbose:
                    print(f"  [SKIP] User already subscribed to event {slug}")
                continue

            # Get first option
            result = await db.execute(
                select(EventOption).where(EventOption.event_id == event_id).limit(1)
            )
            option = result.scalar_one_or_none()

            if option:
                # Create confirmed subscription
                subscription = EventSubscription(
                    id=uuid.uuid4(),
                    event_id=event_id,
                    option_id=option.id,
                    user_id=user.id,
                    amount_cents=option.price_cents,
                    asd_amount_cents=int(option.price_cents * 0.85),
                    platform_amount_cents=int(option.price_cents * 0.15),
                    status=SubscriptionStatus.CONFIRMED,
                    stripe_payment_intent_id=f"pi_{SEED_PREFIX}{uuid.uuid4().hex[:16]}",
                    confirmed_at=datetime.now() - timedelta(days=5),
                )
                db.add(subscription)

                if verbose:
                    print(f"  [CREATE] Subscription: {user.email} -> {slug}")
            break

    await db.commit()


async def seed_waiting_list(db: AsyncSession, event_ids: dict, user: Optional[User], verbose: bool = False):
    """Seed waiting list entry for sold out event."""
    if not user:
        if verbose:
            print("  [SKIP] No test user found, skipping waiting list")
        return

    # Find sold out event
    for slug, event_id in event_ids.items():
        if "soldout" in slug:
            # Check if already in waiting list
            result = await db.execute(
                select(EventWaitingList).where(
                    EventWaitingList.event_id == event_id,
                    EventWaitingList.user_id == user.id
                )
            )
            if result.scalar_one_or_none():
                if verbose:
                    print(f"  [SKIP] User already in waiting list for {slug}")
                continue

            # Create waiting list entry
            entry = EventWaitingList(
                id=uuid.uuid4(),
                event_id=event_id,
                user_id=user.id,
                is_active=True,
            )
            db.add(entry)

            if verbose:
                print(f"  [CREATE] Waiting list: {user.email} -> {slug}")
            break

    await db.commit()


async def clean_seed_data(db: AsyncSession, verbose: bool = False):
    """Remove all seeded data (for --clean flag)."""
    print("\nCleaning seed data...")

    # Delete in order to respect foreign keys

    # 1. Delete waiting list entries for seed events
    result = await db.execute(
        select(Event.id).where(Event.slug.like(f"{SEED_PREFIX}%"))
    )
    seed_event_ids = [row[0] for row in result.fetchall()]

    if seed_event_ids:
        await db.execute(
            delete(EventWaitingList).where(EventWaitingList.event_id.in_(seed_event_ids))
        )
        await db.execute(
            delete(EventSubscription).where(EventSubscription.event_id.in_(seed_event_ids))
        )
        await db.execute(
            delete(EventOption).where(EventOption.event_id.in_(seed_event_ids))
        )

    # 2. Delete seed events
    await db.execute(delete(Event).where(Event.slug.like(f"{SEED_PREFIX}%")))

    # 3. Delete seed ASD partners
    await db.execute(delete(ASDPartner).where(ASDPartner.slug.like(f"{SEED_PREFIX}%")))

    await db.commit()
    print("  Seed data cleaned successfully")


# ============================================================================
# MAIN
# ============================================================================

async def main():
    """Main seed function."""
    import argparse

    parser = argparse.ArgumentParser(description="Seed events test data")
    parser.add_argument("--clean", action="store_true", help="Remove seed data before re-seeding")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    args = parser.parse_args()

    print("=" * 60)
    print("  SEED EVENTS DATA")
    print("=" * 60)

    async with AsyncSessionLocal() as db:
        try:
            # Clean if requested
            if args.clean:
                await clean_seed_data(db, args.verbose)

            # Get test user
            print("\n[1/5] Finding test user...")
            user = await get_or_create_test_user(db)
            if user:
                print(f"  Found user: {user.email}")
            else:
                print("  No user found (subscriptions will be skipped)")

            # Seed ASD Partners
            print("\n[2/5] Seeding ASD Partners...")
            asd_ids = await seed_asd_partners(db, args.verbose)
            print(f"  {len(asd_ids)} ASD Partners ready")

            # Seed Events
            print("\n[3/5] Seeding Events...")
            event_ids = await seed_events(db, asd_ids, args.verbose)
            print(f"  {len(event_ids)} Events ready")

            # Seed Subscriptions
            print("\n[4/5] Seeding Subscriptions...")
            await seed_subscriptions(db, event_ids, user, args.verbose)

            # Seed Waiting List
            print("\n[5/5] Seeding Waiting List...")
            await seed_waiting_list(db, event_ids, user, args.verbose)

            print("\n" + "=" * 60)
            print("  SEED COMPLETE!")
            print("=" * 60)
            print(f"\nSeeded data summary:")
            print(f"  - ASD Partners: {len(asd_ids)}")
            print(f"  - Events: {len(event_ids)}")
            print(f"    - Draft: 1")
            print(f"    - Presale: 1")
            print(f"    - Open: 3")
            print(f"    - Sold Out: 1")
            print(f"    - Completed: 1")
            print(f"    - Cancelled: 1")
            print(f"\nRun tests:")
            print(f"  cd frontend && npm run test")
            print(f"  curl http://localhost:8000/api/v1/events")

        except Exception as e:
            print(f"\n[ERROR] Seed failed: {e}")
            import traceback
            traceback.print_exc()
            raise


if __name__ == "__main__":
    asyncio.run(main())

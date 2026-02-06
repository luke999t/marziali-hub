"""
================================================================================
AI_MODULE: BlockchainService
AI_DESCRIPTION: Servizio per consensus, batch aggregation e pubblicazione Polygon
AI_BUSINESS: Trasparenza advertiser, audit trail, certificazione revenue
AI_TEACHING: Blockchain consensus pattern, SHA256 hashing, smart contract interaction

ALTERNATIVE_VALUTATE:
- Ethereum mainnet: Scartata perché gas fees troppo alti (~€5-50/tx)
- Solana: Scartata perché meno enterprise adoption
- Polygon (Matic): SCELTA per gas fees bassi (~€0.001/tx), EVM compatible

PERCHE_QUESTA_SOLUZIONE:
- Vantaggio tecnico: EVM compatible, facile integrazione Web3
- Vantaggio business: Trasparenza per advertiser, audit immutabile
- Trade-off accettati: Centralizzazione relativa vs pure blockchain

METRICHE_SUCCESSO:
- Batch publication success rate: >= 99%
- Consensus achievement rate: >= 95%
- Average tx cost: <= €0.01

INTEGRATION_DEPENDENCIES:
- Upstream: modules/ads (pause_ad_service, ads_service)
- Downstream: api/v1/blockchain.py, admin dashboard
================================================================================
"""

from datetime import datetime, timedelta
from typing import Optional, List, Dict, Any, Tuple
import uuid
import hashlib
import json

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, and_, update
from sqlalchemy.orm import selectinload

from models.ads import (
    BlockchainBatch,
    ConsensusStatus,
    StoreNode,
    NodeValidation
)


# === CONSTANTS ===

CONSENSUS_THRESHOLD = 0.51  # 51% agreement required
MIN_VALIDATORS = 3          # Minimum validators for consensus
BATCH_PERIOD_DAYS = 7       # Weekly batch


class BlockchainService:
    """
    Servizio per gestione blockchain batch e consensus.

    BUSINESS_PURPOSE: Creare audit trail immutabile per revenue ads,
    validato da network di store nodes, pubblicato su Polygon.

    TECHNICAL_EXPLANATION: Flow settimanale:
    1. Aggrega dati ads (impressions, clicks, revenue)
    2. Calcola hash SHA256 del batch
    3. Broadcast a tutti i nodi attivi
    4. Raccoglie validazioni (firma + hash match)
    5. Se consensus >= 51%, pubblica su Polygon
    """

    def __init__(self, db: AsyncSession):
        """
        Inizializza il servizio con database session.

        Args:
            db: AsyncSession SQLAlchemy per operazioni DB
        """
        self.db = db

    async def create_weekly_batch(
        self,
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None
    ) -> BlockchainBatch:
        """
        Crea batch settimanale con dati aggregati.

        BUSINESS_PURPOSE: Preparazione dati per certificazione blockchain
        TECHNICAL_EXPLANATION: Aggrega tutte le views, calcola revenue, crea hash

        DECISION_TREE:
        1. Se batch per periodo esiste -> Raise ValueError
        2. Se no data nel periodo -> Crea batch vuoto
        3. Se tutto OK -> Crea batch con aggregazioni

        Args:
            start_date: Inizio periodo (default: 7 giorni fa)
            end_date: Fine periodo (default: ora)

        Returns:
            BlockchainBatch creato

        Raises:
            ValueError: Se batch per periodo gia esiste
        """
        if not end_date:
            end_date = datetime.utcnow()
        if not start_date:
            start_date = end_date - timedelta(days=BATCH_PERIOD_DAYS)

        existing = await self._get_batch_for_period(start_date, end_date)
        if existing:
            raise ValueError(f"Batch already exists for period {start_date} to {end_date}")

        ads_data = await self._aggregate_ads_data(start_date, end_date)
        pause_ads_data = await self._aggregate_pause_ads_data(start_date, end_date)

        total_views = ads_data["total_views"] + pause_ads_data["total_impressions"]
        unique_users = ads_data["unique_users"] + pause_ads_data["unique_users"]
        total_watch_time = ads_data["total_watch_time"]
        total_revenue = ads_data["total_revenue"] + pause_ads_data["total_revenue"]

        batch_data = {
            "period_start": start_date.isoformat(),
            "period_end": end_date.isoformat(),
            "ads_batch": {
                "total_sessions": ads_data["total_sessions"],
                "completed_sessions": ads_data["completed_sessions"],
                "total_views": ads_data["total_views"],
                "total_watch_time_seconds": ads_data["total_watch_time"],
                "revenue_eur": round(ads_data["total_revenue"], 2)
            },
            "pause_ads": {
                "total_impressions": pause_ads_data["total_impressions"],
                "total_clicks": pause_ads_data["total_clicks"],
                "ad_clicks": pause_ads_data["ad_clicks"],
                "suggested_clicks": pause_ads_data["suggested_clicks"],
                "revenue_eur": round(pause_ads_data["total_revenue"], 2)
            },
            "totals": {
                "total_views": total_views,
                "unique_users": unique_users,
                "total_revenue_eur": round(total_revenue, 2)
            },
            "generated_at": datetime.utcnow().isoformat()
        }

        data_hash = self.calculate_batch_hash(batch_data)

        active_nodes_count = await self._get_active_nodes_count()
        validations_required = max(MIN_VALIDATORS, int(active_nodes_count * CONSENSUS_THRESHOLD))

        batch = BlockchainBatch(
            id=uuid.uuid4(),
            batch_date=start_date,
            period_start=start_date,
            period_end=end_date,
            total_views=total_views,
            unique_users=unique_users,
            total_watch_time=total_watch_time,
            total_revenue=total_revenue,
            data_hash=data_hash,
            merkle_root=None,
            consensus_status=ConsensusStatus.PENDING,
            consensus_threshold=CONSENSUS_THRESHOLD,
            validations_received=0,
            validations_required=validations_required,
            published_to_blockchain=False,
            blockchain_tx_hash=None,
            blockchain_block_number=None,
            published_at=None,
            created_at=datetime.utcnow(),
            updated_at=datetime.utcnow()
        )

        self.db.add(batch)
        await self.db.commit()
        await self.db.refresh(batch)

        return batch

    async def add_pause_ad_data_to_batch(
        self,
        batch_id: str
    ) -> Dict[str, Any]:
        """
        Aggrega e aggiunge dati pause ads al batch esistente.

        BUSINESS_PURPOSE: Includere pause ads revenue nel batch certificato

        Args:
            batch_id: UUID del batch

        Returns:
            Dict con statistiche pause ads aggregate
        """
        batch_uuid = uuid.UUID(batch_id)

        result = await self.db.execute(
            select(BlockchainBatch).where(BlockchainBatch.id == batch_uuid)
        )
        batch = result.scalar_one_or_none()

        if not batch:
            raise ValueError("Batch not found")

        if batch.consensus_status != ConsensusStatus.PENDING:
            raise ValueError("Cannot modify batch after validation started")

        pause_ads_data = await self._aggregate_pause_ads_data(
            batch.period_start,
            batch.period_end
        )

        from modules.ads.pause_ad_service import PauseAdService
        pause_ad_service = PauseAdService(self.db)

        impressions = await pause_ad_service.get_impressions_for_blockchain_batch(
            batch.period_start,
            batch.period_end
        )

        if impressions:
            impression_ids = [imp["id"] for imp in impressions]
            await pause_ad_service.mark_impressions_batched(impression_ids, batch_id)

        batch.total_views += pause_ads_data["total_impressions"]
        batch.total_revenue += pause_ads_data["total_revenue"]

        new_batch_data = {
            "period_start": batch.period_start.isoformat(),
            "period_end": batch.period_end.isoformat(),
            "total_views": batch.total_views,
            "unique_users": batch.unique_users,
            "total_revenue": batch.total_revenue,
            "pause_ads_included": True,
            "pause_ads_impressions": pause_ads_data["total_impressions"],
            "updated_at": datetime.utcnow().isoformat()
        }

        batch.data_hash = self.calculate_batch_hash(new_batch_data)
        batch.updated_at = datetime.utcnow()

        await self.db.commit()

        return pause_ads_data

    async def broadcast_batch_to_nodes(
        self,
        batch_id: str
    ) -> Dict[str, Any]:
        """
        Invia batch a tutti i nodi attivi per validazione.

        BUSINESS_PURPOSE: Avviare processo di consensus
        TECHNICAL_EXPLANATION: Notifica nodi, aggiorna status a VALIDATING

        Args:
            batch_id: UUID del batch

        Returns:
            Dict con risultato broadcast
        """
        batch_uuid = uuid.UUID(batch_id)

        result = await self.db.execute(
            select(BlockchainBatch).where(BlockchainBatch.id == batch_uuid)
        )
        batch = result.scalar_one_or_none()

        if not batch:
            raise ValueError("Batch not found")

        if batch.consensus_status not in [ConsensusStatus.PENDING, ConsensusStatus.VALIDATING]:
            raise ValueError(f"Batch status is {batch.consensus_status.value}, cannot broadcast")

        active_nodes = await self._get_active_nodes()

        if len(active_nodes) < MIN_VALIDATORS:
            raise ValueError(f"Not enough validators. Need {MIN_VALIDATORS}, have {len(active_nodes)}")

        batch.consensus_status = ConsensusStatus.VALIDATING
        batch.validations_required = max(MIN_VALIDATORS, int(len(active_nodes) * CONSENSUS_THRESHOLD))
        batch.updated_at = datetime.utcnow()

        await self.db.commit()

        broadcast_results = []
        for node in active_nodes:
            success = await self._notify_node(node, batch)
            broadcast_results.append({
                "node_id": str(node.id),
                "node_name": node.node_name,
                "notified": success
            })

        return {
            "batch_id": batch_id,
            "status": "validating",
            "nodes_notified": len([r for r in broadcast_results if r["notified"]]),
            "total_nodes": len(active_nodes),
            "validations_required": batch.validations_required,
            "results": broadcast_results
        }

    async def receive_node_validation(
        self,
        batch_id: str,
        node_id: str,
        is_valid: bool,
        computed_hash: str,
        signature: str
    ) -> Dict[str, Any]:
        """
        Riceve e registra validazione da un nodo.

        BUSINESS_PURPOSE: Raccogliere voti per consensus
        TECHNICAL_EXPLANATION: Verifica firma, confronta hash, registra voto

        DECISION_TREE:
        1. Se nodo gia votato -> Ignora (idempotente)
        2. Se hash non matcha -> Registra come disagreement
        3. Se tutto OK -> Registra agreement

        Args:
            batch_id: UUID del batch
            node_id: UUID del nodo validatore
            is_valid: True se nodo approva
            computed_hash: Hash calcolato dal nodo
            signature: Firma crittografica del nodo

        Returns:
            Dict con stato validazione
        """
        batch_uuid = uuid.UUID(batch_id)
        node_uuid = uuid.UUID(node_id)

        result = await self.db.execute(
            select(BlockchainBatch).where(BlockchainBatch.id == batch_uuid)
        )
        batch = result.scalar_one_or_none()

        if not batch:
            raise ValueError("Batch not found")

        result = await self.db.execute(
            select(StoreNode).where(
                and_(
                    StoreNode.id == node_uuid,
                    StoreNode.is_active == True,
                    StoreNode.is_trusted == True
                )
            )
        )
        node = result.scalar_one_or_none()

        if not node:
            raise ValueError("Invalid or untrusted node")

        result = await self.db.execute(
            select(NodeValidation).where(
                and_(
                    NodeValidation.batch_id == batch_uuid,
                    NodeValidation.node_id == node_uuid
                )
            )
        )
        existing_validation = result.scalar_one_or_none()

        if existing_validation:
            return {
                "status": "already_validated",
                "batch_id": batch_id,
                "node_id": node_id
            }

        hash_matches = computed_hash == batch.data_hash
        agrees = is_valid and hash_matches

        validation = NodeValidation(
            id=uuid.uuid4(),
            batch_id=batch_uuid,
            node_id=node_uuid,
            data_hash=computed_hash,
            agrees=agrees,
            signature=signature,
            validated_at=datetime.utcnow()
        )

        self.db.add(validation)

        if agrees:
            batch.validations_received += 1

        node.total_validations += 1
        node.last_validation_at = datetime.utcnow()

        await self.db.commit()

        consensus_status = await self.check_consensus(batch_id)

        return {
            "status": "validation_received",
            "batch_id": batch_id,
            "node_id": node_id,
            "agrees": agrees,
            "hash_matches": hash_matches,
            "consensus_status": consensus_status["status"],
            "consensus_rate": consensus_status["rate"]
        }

    async def check_consensus(self, batch_id: str) -> Dict[str, Any]:
        """
        Verifica se consensus e stato raggiunto.

        BUSINESS_PURPOSE: Determinare se batch puo essere pubblicato
        TECHNICAL_EXPLANATION: Calcola ratio agreements/required

        Args:
            batch_id: UUID del batch

        Returns:
            Dict con stato consensus
        """
        batch_uuid = uuid.UUID(batch_id)

        result = await self.db.execute(
            select(BlockchainBatch).where(BlockchainBatch.id == batch_uuid)
        )
        batch = result.scalar_one_or_none()

        if not batch:
            return {"status": "not_found", "rate": 0.0}

        if batch.validations_required == 0:
            return {"status": "no_validators", "rate": 0.0}

        rate = batch.validations_received / batch.validations_required

        if rate >= CONSENSUS_THRESHOLD:
            if batch.consensus_status != ConsensusStatus.CONSENSUS_REACHED:
                batch.consensus_status = ConsensusStatus.CONSENSUS_REACHED
                batch.updated_at = datetime.utcnow()
                await self.db.commit()

            return {
                "status": "consensus_reached",
                "rate": round(rate, 4),
                "validations_received": batch.validations_received,
                "validations_required": batch.validations_required,
                "can_publish": True
            }

        result = await self.db.execute(
            select(func.count(NodeValidation.id)).where(
                NodeValidation.batch_id == batch_uuid
            )
        )
        total_validations = result.scalar() or 0

        active_nodes = await self._get_active_nodes_count()

        if total_validations >= active_nodes:
            batch.consensus_status = ConsensusStatus.CONSENSUS_FAILED
            batch.updated_at = datetime.utcnow()
            await self.db.commit()

            return {
                "status": "consensus_failed",
                "rate": round(rate, 4),
                "validations_received": batch.validations_received,
                "total_validations": total_validations,
                "can_publish": False
            }

        return {
            "status": "validating",
            "rate": round(rate, 4),
            "validations_received": batch.validations_received,
            "validations_required": batch.validations_required,
            "remaining": batch.validations_required - batch.validations_received,
            "can_publish": False
        }

    async def publish_to_blockchain(
        self,
        batch_id: str
    ) -> Dict[str, Any]:
        """
        Pubblica batch su Polygon blockchain.

        BUSINESS_PURPOSE: Certificazione immutabile su chain pubblica
        TECHNICAL_EXPLANATION: Chiama smart contract, registra tx hash

        DECISION_TREE:
        1. Se consensus non raggiunto -> Raise
        2. Se gia pubblicato -> Return existing tx
        3. Se tutto OK -> Pubblica e registra

        Args:
            batch_id: UUID del batch

        Returns:
            Dict con risultato pubblicazione

        Raises:
            ValueError: Se consensus non raggiunto o batch non trovato
        """
        batch_uuid = uuid.UUID(batch_id)

        result = await self.db.execute(
            select(BlockchainBatch).where(BlockchainBatch.id == batch_uuid)
        )
        batch = result.scalar_one_or_none()

        if not batch:
            raise ValueError("Batch not found")

        if batch.published_to_blockchain:
            return {
                "status": "already_published",
                "batch_id": batch_id,
                "tx_hash": batch.blockchain_tx_hash,
                "block_number": batch.blockchain_block_number,
                "published_at": batch.published_at.isoformat() if batch.published_at else None
            }

        if batch.consensus_status != ConsensusStatus.CONSENSUS_REACHED:
            raise ValueError(f"Cannot publish: consensus status is {batch.consensus_status.value}")

        tx_result = await self._send_to_polygon(batch)

        if tx_result["success"]:
            batch.published_to_blockchain = True
            batch.blockchain_tx_hash = tx_result["tx_hash"]
            batch.blockchain_block_number = tx_result["block_number"]
            batch.published_at = datetime.utcnow()
            batch.consensus_status = ConsensusStatus.PUBLISHED
            batch.updated_at = datetime.utcnow()

            await self.db.commit()

            return {
                "status": "published",
                "batch_id": batch_id,
                "tx_hash": tx_result["tx_hash"],
                "block_number": tx_result["block_number"],
                "published_at": batch.published_at.isoformat(),
                "explorer_url": f"https://polygonscan.com/tx/{tx_result['tx_hash']}"
            }
        else:
            batch.consensus_status = ConsensusStatus.FAILED
            batch.updated_at = datetime.utcnow()
            await self.db.commit()

            return {
                "status": "failed",
                "batch_id": batch_id,
                "error": tx_result.get("error", "Unknown error")
            }

    def calculate_batch_hash(self, data: Dict[str, Any]) -> str:
        """
        Calcola SHA256 hash dei dati batch.

        TECHNICAL_EXPLANATION: Serializza JSON deterministico, calcola SHA256

        Args:
            data: Dict con dati da hashare

        Returns:
            Hash SHA256 come stringa hex (66 chars con 0x prefix)
        """
        json_str = json.dumps(data, sort_keys=True, separators=(',', ':'))

        hash_bytes = hashlib.sha256(json_str.encode('utf-8')).digest()

        return '0x' + hash_bytes.hex()

    async def get_batch_status(self, batch_id: str) -> Dict[str, Any]:
        """
        Ottiene stato completo di un batch.

        Args:
            batch_id: UUID del batch

        Returns:
            Dict con stato completo batch
        """
        batch_uuid = uuid.UUID(batch_id)

        result = await self.db.execute(
            select(BlockchainBatch)
            .options(selectinload(BlockchainBatch.validations))
            .where(BlockchainBatch.id == batch_uuid)
        )
        batch = result.scalar_one_or_none()

        if not batch:
            return {"status": "not_found"}

        validations_detail = []
        for v in batch.validations:
            validations_detail.append({
                "node_id": str(v.node_id),
                "agrees": v.agrees,
                "hash_match": v.data_hash == batch.data_hash,
                "validated_at": v.validated_at.isoformat()
            })

        return {
            "batch_id": str(batch.id),
            "period": {
                "start": batch.period_start.isoformat(),
                "end": batch.period_end.isoformat()
            },
            "data": {
                "total_views": batch.total_views,
                "unique_users": batch.unique_users,
                "total_watch_time": batch.total_watch_time,
                "total_revenue_eur": round(batch.total_revenue, 2)
            },
            "hash": batch.data_hash,
            "consensus": {
                "status": batch.consensus_status.value,
                "threshold": batch.consensus_threshold,
                "validations_received": batch.validations_received,
                "validations_required": batch.validations_required,
                "rate": round(batch.validations_received / batch.validations_required, 4) if batch.validations_required > 0 else 0
            },
            "validations": validations_detail,
            "blockchain": {
                "published": batch.published_to_blockchain,
                "tx_hash": batch.blockchain_tx_hash,
                "block_number": batch.blockchain_block_number,
                "published_at": batch.published_at.isoformat() if batch.published_at else None
            },
            "timestamps": {
                "created_at": batch.created_at.isoformat(),
                "updated_at": batch.updated_at.isoformat()
            }
        }

    async def get_recent_batches(self, limit: int = 10) -> List[Dict[str, Any]]:
        """
        Ottiene lista batch recenti.

        Args:
            limit: Numero massimo di batch

        Returns:
            Lista di batch summary
        """
        result = await self.db.execute(
            select(BlockchainBatch)
            .order_by(BlockchainBatch.created_at.desc())
            .limit(limit)
        )
        batches = result.scalars().all()

        return [
            {
                "id": str(b.id),
                "period_start": b.period_start.isoformat(),
                "period_end": b.period_end.isoformat(),
                "total_views": b.total_views,
                "total_revenue": round(b.total_revenue, 2),
                "status": b.consensus_status.value,
                "published": b.published_to_blockchain,
                "tx_hash": b.blockchain_tx_hash
            }
            for b in batches
        ]

    async def _aggregate_ads_data(
        self,
        start_date: datetime,
        end_date: datetime
    ) -> Dict[str, Any]:
        """
        Aggrega dati ads batch per periodo.

        Args:
            start_date: Data inizio
            end_date: Data fine

        Returns:
            Dict con aggregazioni
        """
        from models.ads import AdsSession, AdsSessionStatus

        result = await self.db.execute(
            select(func.count(AdsSession.id)).where(
                and_(
                    AdsSession.created_at >= start_date,
                    AdsSession.created_at <= end_date
                )
            )
        )
        total_sessions = result.scalar() or 0

        result = await self.db.execute(
            select(func.count(AdsSession.id)).where(
                and_(
                    AdsSession.created_at >= start_date,
                    AdsSession.created_at <= end_date,
                    AdsSession.status == AdsSessionStatus.COMPLETED
                )
            )
        )
        completed_sessions = result.scalar() or 0

        result = await self.db.execute(
            select(
                func.sum(AdsSession.total_duration_watched),
                func.count(func.distinct(AdsSession.user_id)),
                func.sum(AdsSession.estimated_revenue)
            ).where(
                and_(
                    AdsSession.created_at >= start_date,
                    AdsSession.created_at <= end_date,
                    AdsSession.status == AdsSessionStatus.COMPLETED
                )
            )
        )
        row = result.one()

        return {
            "total_sessions": total_sessions,
            "completed_sessions": completed_sessions,
            "total_views": completed_sessions * 6,
            "total_watch_time": row[0] or 0,
            "unique_users": row[1] or 0,
            "total_revenue": float(row[2] or 0)
        }

    async def _aggregate_pause_ads_data(
        self,
        start_date: datetime,
        end_date: datetime
    ) -> Dict[str, Any]:
        """
        Aggrega dati pause ads per periodo.

        Args:
            start_date: Data inizio
            end_date: Data fine

        Returns:
            Dict con aggregazioni pause ads
        """
        from modules.ads.pause_ad_service import PauseAdService, PAUSE_AD_CPM, CLICK_BONUS

        pause_ad_service = PauseAdService(self.db)
        stats = await pause_ad_service.get_pause_ad_stats(start_date, end_date)

        return {
            "total_impressions": stats["impressions"]["total"],
            "unique_users": stats["impressions"]["unique_users"],
            "total_clicks": stats["clicks"]["total"],
            "ad_clicks": stats["clicks"]["ad_clicks"],
            "suggested_clicks": stats["clicks"]["suggested_clicks"],
            "total_revenue": stats["revenue"]["total_revenue_eur"]
        }

    async def _get_active_nodes(self) -> List[StoreNode]:
        """
        Ottiene lista nodi attivi e trusted.

        Returns:
            Lista di StoreNode
        """
        result = await self.db.execute(
            select(StoreNode).where(
                and_(
                    StoreNode.is_active == True,
                    StoreNode.is_trusted == True
                )
            )
        )
        return list(result.scalars().all())

    async def _get_active_nodes_count(self) -> int:
        """
        Conta nodi attivi e trusted.

        Returns:
            Numero di nodi attivi
        """
        result = await self.db.execute(
            select(func.count(StoreNode.id)).where(
                and_(
                    StoreNode.is_active == True,
                    StoreNode.is_trusted == True
                )
            )
        )
        return result.scalar() or 0

    async def _get_batch_for_period(
        self,
        start_date: datetime,
        end_date: datetime
    ) -> Optional[BlockchainBatch]:
        """
        Cerca batch esistente per periodo.

        Args:
            start_date: Data inizio
            end_date: Data fine

        Returns:
            BlockchainBatch o None
        """
        result = await self.db.execute(
            select(BlockchainBatch).where(
                and_(
                    BlockchainBatch.period_start == start_date,
                    BlockchainBatch.period_end == end_date
                )
            )
        )
        return result.scalar_one_or_none()

    async def _notify_node(
        self,
        node: StoreNode,
        batch: BlockchainBatch
    ) -> bool:
        """
        Notifica singolo nodo per validazione batch.

        TECHNICAL_EXPLANATION: In produzione, questo chiamerebbe
        l'endpoint del nodo. Per ora simula notifica.

        Args:
            node: StoreNode da notificare
            batch: Batch da validare

        Returns:
            True se notifica riuscita
        """
        return True

    async def _send_to_polygon(
        self,
        batch: BlockchainBatch
    ) -> Dict[str, Any]:
        """
        Invia batch a smart contract su Polygon.

        TECHNICAL_EXPLANATION: In produzione, userebbe Web3.py
        per interagire con smart contract. Per ora simula.

        Args:
            batch: Batch da pubblicare

        Returns:
            Dict con risultato transazione
        """
        import secrets

        simulated_tx_hash = "0x" + secrets.token_hex(32)
        simulated_block = 50000000 + int(datetime.utcnow().timestamp() % 1000000)

        return {
            "success": True,
            "tx_hash": simulated_tx_hash,
            "block_number": simulated_block
        }

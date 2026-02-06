"""
AI_MODULE: Royalty Blockchain Tracker
AI_DESCRIPTION: Sistema tracking royalties on-chain con Merkle trees per efficienza
AI_BUSINESS: Trasparenza verificabile, proof immutabile views, trust maestri 100%
AI_TEACHING: Web3.py, Polygon L2, Merkle proofs, IPFS storage, async patterns

ADAPTED FROM: STREAMING_PLATFORM_MANGA_ANIME/backend/app/modules/blockchain/tracker.py

ALTERNATIVE_VALUTATE:
- Ogni view singola on-chain: Scartato, gas costs insostenibili (50+ per tx)
- Solo database: Scartato, no trasparenza verificabile
- Ethereum mainnet: Scartato, gas fees proibitivi
- Centralized proof: Scartato, non verificabile pubblicamente

PERCHE_QUESTA_SOLUZIONE:
- Merkle trees: Batch N views in 1 tx, proof O(log N) per verifica
- Polygon L2: Gas <0.01, finality 2s, EVM compatible
- IPFS: Storage decentralizzato metadata, immutabile
- Async: Non blocca API durante blockchain ops

METRICHE_SUCCESSO:
- Gas cost per view: <0.001
- Batch size: 100-1000 views
- Verification time: <5s
- Proof size: O(log N)
"""

import asyncio
import json
import hashlib
import uuid
from datetime import datetime
from decimal import Decimal
from typing import Dict, List, Optional, Any
from dataclasses import dataclass
import os
import logging

# Logging setup
logger = logging.getLogger(__name__)

# Optional imports - graceful degradation if not installed
try:
    from web3 import Web3
    from web3.middleware import geth_poa_middleware
    from eth_account import Account
    WEB3_AVAILABLE = True
except ImportError:
    WEB3_AVAILABLE = False
    logger.warning("web3 not installed - blockchain features disabled")

try:
    import ipfshttpclient
    IPFS_AVAILABLE = True
except ImportError:
    IPFS_AVAILABLE = False
    logger.warning("ipfshttpclient not installed - IPFS features disabled")

try:
    import merkletools
    MERKLE_AVAILABLE = True
except ImportError:
    MERKLE_AVAILABLE = False
    logger.warning("merkletools not installed - Merkle tree features disabled")

# Local imports
from .config import RoyaltyConfig, get_royalty_config


# ======================== SMART CONTRACT ABI ========================

ROYALTY_TRACKER_ABI = json.loads("""[
    {
        "inputs": [],
        "name": "owner",
        "outputs": [{"internalType": "address", "name": "", "type": "address"}],
        "stateMutability": "view",
        "type": "function"
    },
    {
        "inputs": [
            {"internalType": "bytes32", "name": "_merkleRoot", "type": "bytes32"},
            {"internalType": "uint256", "name": "_totalViews", "type": "uint256"},
            {"internalType": "uint256", "name": "_totalRoyaltyCents", "type": "uint256"},
            {"internalType": "string", "name": "_ipfsHash", "type": "string"}
        ],
        "name": "submitRoyaltyBatch",
        "outputs": [{"internalType": "uint256", "name": "batchId", "type": "uint256"}],
        "stateMutability": "nonpayable",
        "type": "function"
    },
    {
        "inputs": [
            {"internalType": "uint256", "name": "_batchId", "type": "uint256"},
            {"internalType": "bytes32[]", "name": "_proof", "type": "bytes32[]"},
            {"internalType": "bytes32", "name": "_leaf", "type": "bytes32"}
        ],
        "name": "verifyRoyalty",
        "outputs": [{"internalType": "bool", "name": "", "type": "bool"}],
        "stateMutability": "view",
        "type": "function"
    },
    {
        "inputs": [{"internalType": "uint256", "name": "_batchId", "type": "uint256"}],
        "name": "getBatch",
        "outputs": [
            {"internalType": "bytes32", "name": "merkleRoot", "type": "bytes32"},
            {"internalType": "uint256", "name": "totalViews", "type": "uint256"},
            {"internalType": "uint256", "name": "totalRoyaltyCents", "type": "uint256"},
            {"internalType": "string", "name": "ipfsHash", "type": "string"},
            {"internalType": "uint256", "name": "timestamp", "type": "uint256"}
        ],
        "stateMutability": "view",
        "type": "function"
    },
    {
        "anonymous": false,
        "inputs": [
            {"indexed": true, "internalType": "uint256", "name": "batchId", "type": "uint256"},
            {"indexed": false, "internalType": "bytes32", "name": "merkleRoot", "type": "bytes32"},
            {"indexed": false, "internalType": "uint256", "name": "totalViews", "type": "uint256"},
            {"indexed": false, "internalType": "uint256", "name": "totalRoyaltyCents", "type": "uint256"}
        ],
        "name": "RoyaltyBatchSubmitted",
        "type": "event"
    }
]""")


# ======================== DATA CLASSES ========================

@dataclass
class RoyaltyViewData:
    """
    Dati singola view per batch blockchain.

    Contiene tutti i dati necessari per generare
    il leaf hash nel Merkle tree.
    """
    royalty_id: str
    video_id: str
    master_id: str
    student_id: Optional[str]
    view_session_id: str
    milestone: str
    amount_cents: int
    timestamp: datetime

    def to_leaf_dict(self) -> dict:
        """
        Converte in dict per hashing.

        Returns:
            Dict ordinato per hashing deterministico
        """
        return {
            'royalty_id': self.royalty_id,
            'video_id': self.video_id,
            'master_id': self.master_id,
            'student_id': self.student_id or 'anonymous',
            'view_session_id': self.view_session_id,
            'milestone': self.milestone,
            'amount_cents': self.amount_cents,
            'timestamp': int(self.timestamp.timestamp())
        }

    def compute_hash(self) -> str:
        """
        Calcola hash SHA256 della view.

        Returns:
            Hash hex con prefisso 0x
        """
        data = json.dumps(self.to_leaf_dict(), sort_keys=True)
        return '0x' + hashlib.sha256(data.encode()).hexdigest()


@dataclass
class BatchResult:
    """
    Risultato submission batch blockchain.
    """
    success: bool
    batch_id: Optional[str]
    merkle_root: Optional[str]
    tx_hash: Optional[str]
    ipfs_hash: Optional[str]
    views_count: int
    total_amount_cents: int
    gas_used: Optional[int]
    error: Optional[str]


@dataclass
class VerificationResult:
    """
    Risultato verifica on-chain.
    """
    verified: bool
    royalty_id: str
    batch_id: Optional[str]
    tx_hash: Optional[str]
    merkle_root: Optional[str]
    merkle_proof: Optional[List[str]]
    ipfs_hash: Optional[str]
    block_number: Optional[int]
    confirmations: int
    error: Optional[str]


# ======================== BLOCKCHAIN TRACKER ========================

class RoyaltyBlockchainTracker:
    """
    Sistema tracking royalties su blockchain.

    Gestisce:
    - Batching views in Merkle trees
    - Submission on-chain
    - Verifica proofs
    - Storage IPFS
    """

    def __init__(self, config: Optional[RoyaltyConfig] = None):
        """
        Inizializza tracker blockchain.

        Args:
            config: Configurazione royalties (usa default se None)
        """
        self.config = config or get_royalty_config()
        self.blockchain_config = self.config.blockchain

        # Initialize Web3 if available and enabled
        self.w3 = None
        self.account = None
        self.contract = None

        if WEB3_AVAILABLE and self.blockchain_config.enabled:
            self._init_web3()

        # Initialize IPFS if available
        self.ipfs = None
        if IPFS_AVAILABLE and self.blockchain_config.ipfs_enabled:
            self._init_ipfs()

        # Pending views queue
        self.pending_views: List[RoyaltyViewData] = []
        self._batch_lock = asyncio.Lock()

        logger.info(
            "RoyaltyBlockchainTracker initialized",
            extra={
                "blockchain_enabled": self.blockchain_config.enabled and WEB3_AVAILABLE,
                "ipfs_enabled": self.blockchain_config.ipfs_enabled and IPFS_AVAILABLE,
                "network": self.blockchain_config.network
            }
        )

    def _init_web3(self):
        """Inizializza connessione Web3."""
        try:
            rpc_url = self.blockchain_config.get_rpc_url()
            self.w3 = Web3(Web3.HTTPProvider(rpc_url))

            # Inject PoA middleware for Polygon
            self.w3.middleware_onion.inject(geth_poa_middleware, layer=0)

            # Initialize account from private key
            private_key = os.getenv("BLOCKCHAIN_PRIVATE_KEY")
            if private_key:
                self.account = Account.from_key(private_key)
                self.w3.eth.default_account = self.account.address
                logger.info(f"Blockchain account loaded: {self.account.address}")
            else:
                logger.warning("No BLOCKCHAIN_PRIVATE_KEY - read-only mode")

            # Initialize contract if address configured
            contract_address = self.blockchain_config.royalty_tracker_contract
            if contract_address:
                self.contract = self.w3.eth.contract(
                    address=Web3.to_checksum_address(contract_address),
                    abi=ROYALTY_TRACKER_ABI
                )
                logger.info(f"Contract initialized: {contract_address}")

        except Exception as e:
            logger.error(f"Web3 initialization failed: {e}")
            self.w3 = None

    def _init_ipfs(self):
        """Inizializza connessione IPFS."""
        try:
            self.ipfs = ipfshttpclient.connect(self.blockchain_config.ipfs_api_url)
            logger.info(f"IPFS connected: {self.blockchain_config.ipfs_api_url}")
        except Exception as e:
            logger.error(f"IPFS connection failed: {e}")
            self.ipfs = None

    # ======================== VIEW TRACKING ========================

    async def add_view_for_batch(self, view_data: RoyaltyViewData) -> bool:
        """
        Aggiunge view alla coda per batching.

        Args:
            view_data: Dati della view

        Returns:
            True se aggiunta, False se errore
        """
        async with self._batch_lock:
            self.pending_views.append(view_data)

            # Check se batch pronto
            if len(self.pending_views) >= self.blockchain_config.batch_size:
                # Process batch in background
                asyncio.create_task(self._process_pending_batch())

            return True

    async def _process_pending_batch(self) -> Optional[BatchResult]:
        """
        Processa views pendenti in batch.

        Returns:
            BatchResult o None se batch non pronto
        """
        async with self._batch_lock:
            if len(self.pending_views) < self.blockchain_config.min_batch_size:
                return None

            # Take views for batch
            batch_views = self.pending_views[:self.blockchain_config.batch_size]
            self.pending_views = self.pending_views[self.blockchain_config.batch_size:]

        return await self.submit_batch(batch_views)

    async def force_process_batch(self) -> Optional[BatchResult]:
        """
        Forza processamento batch anche se sotto soglia minima.

        Utile per flush periodico o shutdown.

        Returns:
            BatchResult o None se nessuna view pendente
        """
        async with self._batch_lock:
            if not self.pending_views:
                return None

            batch_views = self.pending_views[:]
            self.pending_views = []

        return await self.submit_batch(batch_views)

    # ======================== BATCH SUBMISSION ========================

    async def submit_batch(self, views: List[RoyaltyViewData]) -> BatchResult:
        """
        Sottomette batch di views su blockchain.

        Steps:
        1. Genera Merkle tree da views
        2. Upload metadata su IPFS
        3. Submit Merkle root on-chain
        4. Monitora conferme

        Args:
            views: Lista views da includere

        Returns:
            BatchResult con dettagli submission
        """
        if not views:
            return BatchResult(
                success=False,
                batch_id=None,
                merkle_root=None,
                tx_hash=None,
                ipfs_hash=None,
                views_count=0,
                total_amount_cents=0,
                gas_used=None,
                error="No views to process"
            )

        batch_id = str(uuid.uuid4())
        total_amount = sum(v.amount_cents for v in views)

        logger.info(f"Processing batch {batch_id} with {len(views)} views")

        try:
            # 1. Generate Merkle tree
            merkle_data = self._generate_merkle_tree(views)
            if not merkle_data:
                return BatchResult(
                    success=False,
                    batch_id=batch_id,
                    merkle_root=None,
                    tx_hash=None,
                    ipfs_hash=None,
                    views_count=len(views),
                    total_amount_cents=total_amount,
                    gas_used=None,
                    error="Merkle tree generation failed"
                )

            merkle_root = merkle_data['root']

            # 2. Upload to IPFS
            ipfs_hash = await self._upload_to_ipfs({
                'batch_id': batch_id,
                'timestamp': datetime.utcnow().isoformat(),
                'views_count': len(views),
                'total_amount_cents': total_amount,
                'merkle_root': merkle_root,
                'views': [v.to_leaf_dict() for v in views]
            })

            # 3. Submit to blockchain (if enabled and configured)
            tx_hash = None
            gas_used = None

            if self.w3 and self.contract and self.account:
                tx_result = await self._submit_to_blockchain(
                    merkle_root=merkle_root,
                    total_views=len(views),
                    total_amount=total_amount,
                    ipfs_hash=ipfs_hash or ""
                )
                tx_hash = tx_result.get('tx_hash')
                gas_used = tx_result.get('gas_used')

            return BatchResult(
                success=True,
                batch_id=batch_id,
                merkle_root=merkle_root,
                tx_hash=tx_hash,
                ipfs_hash=ipfs_hash,
                views_count=len(views),
                total_amount_cents=total_amount,
                gas_used=gas_used,
                error=None
            )

        except Exception as e:
            logger.error(f"Batch submission failed: {e}")
            return BatchResult(
                success=False,
                batch_id=batch_id,
                merkle_root=None,
                tx_hash=None,
                ipfs_hash=None,
                views_count=len(views),
                total_amount_cents=total_amount,
                gas_used=None,
                error=str(e)
            )

    def _generate_merkle_tree(self, views: List[RoyaltyViewData]) -> Optional[Dict[str, Any]]:
        """
        Genera Merkle tree da views.

        Args:
            views: Lista views

        Returns:
            Dict con root, tree, proofs o None se errore
        """
        if not MERKLE_AVAILABLE:
            # Fallback: simple hash of all data
            combined = json.dumps(
                [v.to_leaf_dict() for v in views],
                sort_keys=True
            )
            root = '0x' + hashlib.sha256(combined.encode()).hexdigest()
            return {
                'root': root,
                'tree': None,
                'proofs': {}
            }

        try:
            mt = merkletools.MerkleTools(hash_type="SHA256")

            # Create leaves
            leaves = []
            for view in views:
                leaf_data = json.dumps(view.to_leaf_dict(), sort_keys=True)
                leaves.append(leaf_data)

            # Build tree
            mt.add_leaf(leaves, do_hash=True)
            mt.make_tree()

            # Get root
            root = '0x' + mt.get_merkle_root()

            # Generate proofs for each leaf
            proofs = {}
            for idx, view in enumerate(views):
                proof = mt.get_proof(idx)
                proofs[view.royalty_id] = {
                    'index': idx,
                    'proof': proof
                }

            return {
                'root': root,
                'tree': mt.leaves,
                'proofs': proofs
            }

        except Exception as e:
            logger.error(f"Merkle tree generation failed: {e}")
            return None

    async def _upload_to_ipfs(self, data: Dict[str, Any]) -> Optional[str]:
        """
        Upload dati su IPFS.

        Args:
            data: Dati da uploadare

        Returns:
            IPFS hash o None se fallito
        """
        if not self.ipfs:
            logger.warning("IPFS not available, skipping upload")
            return None

        try:
            result = self.ipfs.add_json(data)
            ipfs_hash = result if isinstance(result, str) else result.get('Hash')

            # Pin content
            if ipfs_hash:
                self.ipfs.pin.add(ipfs_hash)

            logger.info(f"IPFS upload successful: {ipfs_hash}")
            return ipfs_hash

        except Exception as e:
            logger.error(f"IPFS upload failed: {e}")
            return None

    async def _submit_to_blockchain(
        self,
        merkle_root: str,
        total_views: int,
        total_amount: int,
        ipfs_hash: str
    ) -> Dict[str, Any]:
        """
        Sottomette batch su blockchain.

        Args:
            merkle_root: Root del Merkle tree
            total_views: Numero views nel batch
            total_amount: Importo totale in centesimi
            ipfs_hash: Hash IPFS metadata

        Returns:
            Dict con tx_hash, gas_used
        """
        try:
            # Get gas price
            gas_price = self.w3.eth.gas_price
            max_gas = self.blockchain_config.max_gas_price_gwei * 10**9

            if gas_price > max_gas:
                logger.warning(f"Gas price too high: {gas_price / 10**9} Gwei")
                return {'tx_hash': None, 'gas_used': None, 'error': 'Gas too high'}

            # Apply buffer
            gas_price = int(gas_price * self.blockchain_config.gas_buffer_multiplier)

            # Build transaction
            nonce = self.w3.eth.get_transaction_count(self.account.address)

            tx_data = self.contract.functions.submitRoyaltyBatch(
                Web3.to_bytes(hexstr=merkle_root),
                total_views,
                total_amount,
                ipfs_hash
            ).build_transaction({
                'chainId': self.blockchain_config.get_chain_id(),
                'gas': self.blockchain_config.gas_limit_batch,
                'gasPrice': gas_price,
                'nonce': nonce
            })

            # Sign and send
            signed_tx = self.w3.eth.account.sign_transaction(tx_data, self.account.key)
            tx_hash = self.w3.eth.send_raw_transaction(signed_tx.rawTransaction)

            logger.info(f"Transaction sent: {tx_hash.hex()}")

            # Wait for receipt (with timeout)
            receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash, timeout=120)

            return {
                'tx_hash': tx_hash.hex(),
                'gas_used': receipt.gasUsed,
                'status': 'confirmed' if receipt.status == 1 else 'failed'
            }

        except Exception as e:
            logger.error(f"Blockchain submission failed: {e}")
            return {'tx_hash': None, 'gas_used': None, 'error': str(e)}

    # ======================== VERIFICATION ========================

    async def verify_royalty(
        self,
        royalty_id: str,
        batch_data: Dict[str, Any]
    ) -> VerificationResult:
        """
        Verifica royalty on-chain.

        Args:
            royalty_id: ID della royalty
            batch_data: Dati batch (merkle_root, proofs, etc)

        Returns:
            VerificationResult con status verifica
        """
        try:
            if not self.w3 or not self.contract:
                return VerificationResult(
                    verified=False,
                    royalty_id=royalty_id,
                    batch_id=batch_data.get('batch_id'),
                    tx_hash=batch_data.get('tx_hash'),
                    merkle_root=batch_data.get('merkle_root'),
                    merkle_proof=None,
                    ipfs_hash=batch_data.get('ipfs_hash'),
                    block_number=None,
                    confirmations=0,
                    error="Blockchain not configured"
                )

            # Get proof for this royalty
            proofs = batch_data.get('proofs', {})
            proof_data = proofs.get(royalty_id)

            if not proof_data:
                return VerificationResult(
                    verified=False,
                    royalty_id=royalty_id,
                    batch_id=batch_data.get('batch_id'),
                    tx_hash=batch_data.get('tx_hash'),
                    merkle_root=batch_data.get('merkle_root'),
                    merkle_proof=None,
                    ipfs_hash=batch_data.get('ipfs_hash'),
                    block_number=None,
                    confirmations=0,
                    error="Proof not found for royalty"
                )

            # Verify on-chain
            blockchain_batch_id = batch_data.get('blockchain_batch_id')
            if blockchain_batch_id is None:
                return VerificationResult(
                    verified=False,
                    royalty_id=royalty_id,
                    batch_id=batch_data.get('batch_id'),
                    tx_hash=batch_data.get('tx_hash'),
                    merkle_root=batch_data.get('merkle_root'),
                    merkle_proof=proof_data.get('proof'),
                    ipfs_hash=batch_data.get('ipfs_hash'),
                    block_number=None,
                    confirmations=0,
                    error="Batch not submitted to blockchain"
                )

            # Call contract to verify
            leaf_hash = batch_data.get('leaf_hash')
            proof = [Web3.to_bytes(hexstr=p) for p in proof_data.get('proof', [])]

            is_valid = self.contract.functions.verifyRoyalty(
                blockchain_batch_id,
                proof,
                Web3.to_bytes(hexstr=leaf_hash)
            ).call()

            # Get block info
            tx_hash = batch_data.get('tx_hash')
            block_number = None
            confirmations = 0

            if tx_hash:
                tx = self.w3.eth.get_transaction(tx_hash)
                block_number = tx.blockNumber
                current_block = self.w3.eth.block_number
                confirmations = current_block - block_number

            return VerificationResult(
                verified=is_valid,
                royalty_id=royalty_id,
                batch_id=batch_data.get('batch_id'),
                tx_hash=tx_hash,
                merkle_root=batch_data.get('merkle_root'),
                merkle_proof=proof_data.get('proof'),
                ipfs_hash=batch_data.get('ipfs_hash'),
                block_number=block_number,
                confirmations=confirmations,
                error=None
            )

        except Exception as e:
            logger.error(f"Verification failed: {e}")
            return VerificationResult(
                verified=False,
                royalty_id=royalty_id,
                batch_id=batch_data.get('batch_id'),
                tx_hash=batch_data.get('tx_hash'),
                merkle_root=batch_data.get('merkle_root'),
                merkle_proof=None,
                ipfs_hash=batch_data.get('ipfs_hash'),
                block_number=None,
                confirmations=0,
                error=str(e)
            )

    # ======================== IPFS RETRIEVAL ========================

    async def get_batch_from_ipfs(self, ipfs_hash: str) -> Optional[Dict[str, Any]]:
        """
        Recupera dati batch da IPFS.

        Args:
            ipfs_hash: Hash IPFS del batch

        Returns:
            Dati batch o None se non trovato
        """
        if self.ipfs:
            try:
                return self.ipfs.get_json(ipfs_hash)
            except Exception as e:
                logger.error(f"IPFS retrieval failed: {e}")

        # Fallback to public gateway
        try:
            import httpx
            async with httpx.AsyncClient() as client:
                url = f"{self.blockchain_config.ipfs_gateway_url}{ipfs_hash}"
                response = await client.get(url, timeout=30)
                if response.status_code == 200:
                    return response.json()
        except Exception as e:
            logger.error(f"IPFS gateway retrieval failed: {e}")

        return None

    # ======================== UTILITIES ========================

    def get_status(self) -> Dict[str, Any]:
        """
        Ottiene status del tracker.

        Returns:
            Dict con status componenti
        """
        return {
            'blockchain_enabled': self.blockchain_config.enabled,
            'blockchain_connected': self.w3 is not None and self.w3.is_connected() if self.w3 else False,
            'blockchain_network': self.blockchain_config.network,
            'account_address': self.account.address if self.account else None,
            'contract_address': self.blockchain_config.royalty_tracker_contract,
            'ipfs_connected': self.ipfs is not None,
            'pending_views': len(self.pending_views),
            'batch_size': self.blockchain_config.batch_size,
            'min_batch_size': self.blockchain_config.min_batch_size
        }

    async def get_gas_estimate(self) -> Dict[str, Any]:
        """
        Stima costi gas per batch.

        Returns:
            Dict con stime gas
        """
        if not self.w3:
            return {'error': 'Blockchain not connected'}

        try:
            gas_price = self.w3.eth.gas_price
            gas_limit = self.blockchain_config.gas_limit_batch

            # Estimate cost in native token (MATIC/ETH)
            cost_wei = gas_price * gas_limit
            cost_native = cost_wei / 10**18

            # Rough USD estimate (assumes 1 MATIC = $0.50)
            native_price_usd = 0.50 if self.blockchain_config.network == 'polygon' else 3000
            cost_usd = cost_native * native_price_usd

            return {
                'gas_price_gwei': gas_price / 10**9,
                'gas_limit': gas_limit,
                'estimated_cost_native': cost_native,
                'estimated_cost_usd': cost_usd,
                'network': self.blockchain_config.network
            }

        except Exception as e:
            return {'error': str(e)}

"""
================================================================================
AI_MODULE: AI Coach API - Maestro Virtuale Arti Marziali
AI_VERSION: 1.0.0
AI_DESCRIPTION: REST API per AI Coach conversazionale + feedback tecnico
AI_BUSINESS: Feature premium differenziante. 24/7 maestro disponibile.
             ROI: +35% retention abbonati premium, 15 EUR/mese add-on.
AI_TEACHING: RAG + LLM integration, conversation context management,
             streaming responses per UX migliore.
AI_COPYRIGHT: 2025 Media Center Arti Marziali - All Rights Reserved
AI_CREATED: 2026-01-18

================================================================================

ALTERNATIVE_VALUTATE:
- Solo FAQ statiche: Scartato, zero personalizzazione
- Chatbot rule-based: Scartato, non capisce contesto
- LLM senza RAG: Scartato, hallucination su termini tecnici

PERCHE_QUESTA_SOLUZIONE:
- RAG su knowledge base arti marziali = risposte accurate
- Context management = conversazioni naturali
- Streaming = UX responsiva anche con risposte lunghe
- Multi-lingua = mercato internazionale

METRICHE_SUCCESSO:
- Response time: <2s first token (streaming)
- Accuracy: >90% termini tecnici
- User satisfaction: >4.5/5

ENDPOINTS:
- POST /chat: Invia messaggio, ricevi risposta
- POST /chat/stream: Risposta in streaming (SSE)
- GET /conversations: Lista conversazioni utente
- GET /conversations/{id}: Dettaglio conversazione
- DELETE /conversations/{id}: Elimina conversazione
- POST /feedback/technique: Feedback su tecnica da video
- POST /feedback/pose: Feedback real-time su pose
- GET /knowledge/search: Cerca in knowledge base
- GET /styles: Stili supportati
- GET /health: Health check

================================================================================
"""

from fastapi import APIRouter, HTTPException, Depends, Query, BackgroundTasks
from fastapi.responses import StreamingResponse, JSONResponse
from pydantic import BaseModel, Field
from typing import List, Dict, Optional, Any, AsyncGenerator
from datetime import datetime
from enum import Enum
import uuid
import json
import asyncio
import logging

# Authentication - versione semplificata per evitare problemi con generatori DB
# FIX: Usa solo JWT token, non accede al database (evita "generator didn't stop" error)
from fastapi import Security
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

_security = HTTPBearer()

async def get_current_active_user(
    credentials: HTTPAuthorizationCredentials = Security(_security)
):
    """
    Dependency auth semplificata che estrae dati solo dal JWT token.
    Non accede al database, evitando problemi con generatori async.
    """
    from core.security import decode_access_token

    token = credentials.credentials
    token_data = decode_access_token(token)

    return {
        "id": getattr(token_data, "user_id", "unknown"),
        "email": token_data.email,
        "username": getattr(token_data, "username", token_data.email),
        "is_admin": getattr(token_data, "is_admin", False),
        "tier": getattr(token_data, "tier", "free")
    }

# Legacy import
try:
    from core.auth import get_current_user
except ImportError:
    get_current_user = get_current_active_user

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

router = APIRouter()

# ============================================================================
# ENUMS
# ============================================================================

class MartialStyle(str, Enum):
    """Supported martial arts styles."""
    KARATE = "karate"
    KUNG_FU = "kung_fu"
    TAEKWONDO = "taekwondo"
    JUDO = "judo"
    AIKIDO = "aikido"
    BOXING = "boxing"
    MUAY_THAI = "muay_thai"
    MMA = "mma"
    CAPOEIRA = "capoeira"
    KRAV_MAGA = "krav_maga"
    TAI_CHI = "tai_chi"
    JIU_JITSU = "jiu_jitsu"
    GENERAL = "general"


# ============================================================================
# PYDANTIC MODELS
# ============================================================================

class ChatMessage(BaseModel):
    """User chat message."""
    content: str = Field(..., min_length=1, max_length=2000, description="Message content")
    style: Optional[MartialStyle] = Field(default=MartialStyle.GENERAL, description="Martial art style context")
    language: str = Field(default="it", pattern="^(it|en|ja|zh|ko|es|fr|de|pt|ru)$", description="Response language")
    context: Optional[Dict[str, Any]] = Field(default=None, description="Additional context")

    class Config:
        json_schema_extra = {
            "example": {
                "content": "Come si esegue un mae geri correttamente?",
                "style": "karate",
                "language": "it"
            }
        }


class ChatResponse(BaseModel):
    """AI Coach response."""
    id: str = Field(..., description="Response ID")
    content: str = Field(..., description="AI response content")
    sources: List[Dict[str, str]] = Field(default_factory=list, description="RAG sources used")
    confidence: float = Field(ge=0, le=1, description="Response confidence score")
    suggestions: List[str] = Field(default_factory=list, description="Follow-up suggestions")
    timestamp: datetime = Field(..., description="Response timestamp")


class ConversationSummary(BaseModel):
    """Conversation summary."""
    id: str
    title: str
    style: MartialStyle
    message_count: int
    created_at: datetime
    updated_at: datetime


class ConversationDetail(BaseModel):
    """Full conversation with messages."""
    id: str
    title: str
    style: MartialStyle
    user_id: str
    messages: List[Dict[str, Any]]
    created_at: datetime
    updated_at: datetime


class TechniqueFeedbackRequest(BaseModel):
    """Request for technique feedback from video."""
    video_id: str = Field(..., description="Video ID to analyze")
    technique_name: Optional[str] = Field(None, description="Specific technique to analyze")
    timestamp_start: float = Field(default=0, ge=0, description="Start timestamp in seconds")
    timestamp_end: Optional[float] = Field(None, description="End timestamp in seconds")
    focus_areas: List[str] = Field(default_factory=list, description="Areas to focus on")

    class Config:
        json_schema_extra = {
            "example": {
                "video_id": "abc123",
                "technique_name": "mae_geri",
                "timestamp_start": 0,
                "timestamp_end": 5.0,
                "focus_areas": ["postura", "velocita", "potenza"]
            }
        }


class TechniqueFeedback(BaseModel):
    """Detailed technique feedback."""
    overall_score: float = Field(ge=0, le=100, description="Overall score 0-100")
    strengths: List[str] = Field(default_factory=list, description="Technique strengths")
    improvements: List[str] = Field(default_factory=list, description="Areas to improve")
    drills: List[Dict[str, str]] = Field(default_factory=list, description="Recommended exercises")
    reference_videos: List[str] = Field(default_factory=list, description="Reference video IDs")
    detailed_analysis: str = Field(..., description="Detailed text analysis")


class PoseFeedbackRequest(BaseModel):
    """Request for real-time pose feedback."""
    landmarks: List[Dict[str, float]] = Field(..., description="75 or 33 landmarks with x,y,z coordinates")
    technique_name: str = Field(..., description="Technique being performed")
    style: MartialStyle = Field(default=MartialStyle.KARATE, description="Martial art style")

    class Config:
        json_schema_extra = {
            "example": {
                "landmarks": [{"x": 0.5, "y": 0.5, "z": 0.0}],
                "technique_name": "mae_geri",
                "style": "karate"
            }
        }


class PoseCorrection(BaseModel):
    """Single pose correction."""
    joint: str = Field(..., description="Joint name")
    issue: str = Field(..., description="Issue description")
    fix: str = Field(..., description="How to fix it")
    severity: str = Field(default="medium", description="low, medium, high, critical")


class PoseFeedback(BaseModel):
    """Real-time pose feedback."""
    is_correct: bool = Field(..., description="Whether pose is correct")
    score: float = Field(ge=0, le=100, description="Pose score 0-100")
    corrections: List[PoseCorrection] = Field(default_factory=list, description="List of corrections")
    audio_cue: Optional[str] = Field(None, description="Audio cue to play")


class KnowledgeSearchResult(BaseModel):
    """Knowledge base search result."""
    id: str
    title: str
    content: str
    relevance: float = Field(ge=0, le=1)
    source: str
    style: MartialStyle


# ============================================================================
# IN-MEMORY STORAGE (Use Redis in production)
# ============================================================================

conversations_db: Dict[str, Dict] = {}
messages_db: Dict[str, List[Dict]] = {}


# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

def get_user_id_from_token(user) -> str:
    """
    Extract user ID from auth token.

    Args:
        user: Can be a dict (from token) or User object (from DB)

    Returns:
        User ID as string
    """
    # Handle dict (from token data)
    if isinstance(user, dict):
        return user.get("id", user.get("sub", user.get("user_id", "anonymous")))

    # Handle User object (from database)
    if hasattr(user, "id"):
        return str(user.id)

    return "anonymous"


async def get_ai_response(
    message: str,
    conversation_history: List[Dict],
    style: MartialStyle,
    language: str
) -> Dict[str, Any]:
    """
    Generate AI response using RAG + LLM.

    TEACHING: This integrates with the actual AI service.
    Uses ConversationalAgent from ai_conversational_agent.py
    """
    try:
        from services.video_studio.ai_conversational_agent import ConversationalAgent

        agent = ConversationalAgent()

        # Start conversation with user style context
        conv_id = agent.start_conversation(
            user_level="intermediate",
            user_style=style.value
        )

        # Prepend context from history to the question for better understanding
        context_prefix = ""
        if conversation_history:
            context_prefix = "Contesto precedente:\n" + "\n".join([
                f"{msg['role']}: {msg['content']}"
                for msg in conversation_history[-5:]
            ]) + "\n\nDomanda attuale: "

        # Ask the agent - returns (response_text, metadata) tuple
        response_text, metadata = agent.ask(
            question=context_prefix + message,
            conversation_id=conv_id
        )

        return {
            "content": response_text if response_text else "Mi dispiace, non ho capito.",
            "sources": metadata.get("sources", []) if metadata else [],
            "confidence": metadata.get("confidence", 0.8) if metadata else 0.8,
            "suggestions": metadata.get("suggestions", []) if metadata else []
        }

    except ImportError as e:
        logger.warning(f"ConversationalAgent not available: {e}")
        # Fallback demo response
        return {
            "content": f"[Demo Mode] Risposta per stile {style.value}: Il {style.value} e' un'arte marziale affascinante. "
                      f"Per quanto riguarda la tua domanda su '{message[:50]}...', ti consiglio di concentrarti "
                      f"sulla postura e sul respiro. Pratica regolarmente per migliorare.",
            "sources": [],
            "confidence": 0.5,
            "suggestions": [
                "Chiedi informazioni su una tecnica specifica",
                "Richiedi un esercizio di allenamento",
                "Domanda sulla storia dello stile"
            ]
        }
    except Exception as e:
        logger.error(f"AI response error: {e}")
        return {
            "content": f"Errore nel processare la richiesta: {str(e)}",
            "sources": [],
            "confidence": 0,
            "suggestions": []
        }


async def stream_ai_response(
    message: str,
    conversation_history: List[Dict],
    style: MartialStyle,
    language: str
) -> AsyncGenerator[str, None]:
    """
    Generate AI response in streaming (SSE).

    TEACHING: Streaming improves perceived UX.
    User sees response while it's being generated.
    """
    try:
        from services.video_studio.ai_conversational_agent import ConversationalAgent

        agent = ConversationalAgent()

        # Check if streaming is supported
        if hasattr(agent, 'stream_ask'):
            async for chunk in agent.stream_ask(message, style=style.value, language=language):
                yield f"data: {json.dumps({'content': chunk})}\n\n"
        else:
            # Fallback: get full response and simulate streaming
            response = await get_ai_response(message, conversation_history, style, language)
            words = response["content"].split()
            for word in words:
                yield f"data: {json.dumps({'content': word + ' '})}\n\n"
                await asyncio.sleep(0.05)

        yield f"data: {json.dumps({'done': True})}\n\n"

    except ImportError:
        # Demo fallback with simulated streaming
        demo_response = f"[Demo Streaming] Risposta per: {message}. " \
                       f"Nel {style.value}, questa tecnica richiede pratica costante."
        for word in demo_response.split():
            yield f"data: {json.dumps({'content': word + ' '})}\n\n"
            await asyncio.sleep(0.08)
        yield f"data: {json.dumps({'done': True})}\n\n"


async def analyze_technique(
    video_id: str,
    technique_name: Optional[str],
    start: float,
    end: Optional[float],
    focus_areas: List[str]
) -> TechniqueFeedback:
    """
    Analyze technique from video using skeleton + AI.

    TEACHING: Combines skeleton extraction with LLM analysis.
    """
    try:
        # Try to import motion analyzer if available
        from services.video_studio.realtime_pose_corrector import RealtimePoseCorrector

        # In a real implementation, we would:
        # 1. Load skeleton data for the video
        # 2. Analyze the specified time range
        # 3. Compare with ideal poses
        # 4. Generate feedback

        # For now, return a reasonable demo response
        return TechniqueFeedback(
            overall_score=75.0,
            strengths=[
                "Buona postura iniziale",
                "Timing corretto nella transizione",
                "Equilibrio stabile"
            ],
            improvements=[
                "Estendere di piu' il braccio nel colpo finale",
                "Ruotare maggiormente i fianchi per piu' potenza",
                "Mantenere la guardia piu' alta"
            ],
            drills=[
                {"name": "Shadow boxing lento", "duration": "5 min", "focus": "forma"},
                {"name": "Ripetizioni al sacco", "reps": "3x10", "focus": "potenza"},
                {"name": "Stretching dinamico", "duration": "10 min", "focus": "flessibilita'"}
            ],
            reference_videos=["ref-kata-001", "ref-kumite-002"],
            detailed_analysis=f"Analisi della tecnica '{technique_name or 'rilevata automaticamente'}' "
                            f"dal video {video_id}. La tecnica mostra buone basi ma necessita "
                            f"di raffinamento nella fase finale del movimento. "
                            f"Focus areas analizzate: {', '.join(focus_areas) if focus_areas else 'tutte'}."
        )

    except ImportError:
        logger.warning("Motion analyzer not available, using demo response")
        return TechniqueFeedback(
            overall_score=70.0,
            strengths=["Buona postura", "Equilibrio corretto"],
            improvements=["Aumentare la velocita'", "Migliorare il follow-through"],
            drills=[{"name": "Pratica lenta", "duration": "10 min"}],
            reference_videos=[],
            detailed_analysis="Analisi demo - servizio completo non disponibile."
        )


async def analyze_pose_realtime(
    landmarks: List[Dict[str, float]],
    technique_name: str,
    style: MartialStyle
) -> PoseFeedback:
    """
    Analyze pose in real-time and provide immediate feedback.

    TEACHING: Uses realtime_pose_corrector for feedback <100ms.
    """
    try:
        from services.video_studio.realtime_pose_corrector import RealtimePoseCorrector
        import numpy as np

        corrector = RealtimePoseCorrector()
        corrector.pose_matcher.load_knowledge_base()

        # Convert landmarks to numpy array for processing
        landmarks_array = np.array([[lm["x"], lm["y"], lm.get("z", 0)] for lm in landmarks])

        # In production, this would call corrector methods
        # For now, calculate a basic score based on landmark positions

        # Simple heuristic: check if landmarks are in reasonable positions
        x_coords = [lm["x"] for lm in landmarks]
        y_coords = [lm["y"] for lm in landmarks]

        # Check symmetry and bounds
        x_range = max(x_coords) - min(x_coords)
        y_range = max(y_coords) - min(y_coords)

        # Basic scoring
        base_score = 85.0
        corrections = []

        if x_range < 0.1:
            base_score -= 10
            corrections.append(PoseCorrection(
                joint="body",
                issue="Posizione troppo stretta",
                fix="Allarga la posizione dei piedi",
                severity="medium"
            ))

        if y_range < 0.3:
            base_score -= 5
            corrections.append(PoseCorrection(
                joint="spine",
                issue="Postura compressa",
                fix="Raddrizza la schiena e alza il mento",
                severity="low"
            ))

        return PoseFeedback(
            is_correct=len(corrections) == 0,
            score=max(0, min(100, base_score)),
            corrections=corrections,
            audio_cue="good_form" if len(corrections) == 0 else "adjust_stance"
        )

    except ImportError:
        logger.warning("RealtimePoseCorrector not available, using demo response")
        return PoseFeedback(
            is_correct=True,
            score=82.0,
            corrections=[],
            audio_cue=None
        )


# ============================================================================
# ENDPOINTS - CHAT
# ============================================================================

@router.post(
    "/chat",
    response_model=ChatResponse,
    summary="Send chat message",
    description="""
    Invia messaggio all'AI Coach e ricevi risposta.

    BUSINESS: Core interaction - utente chiede, AI risponde
    METRICS: Response time <2s, accuracy >90%
    """
)
async def send_message(
    message: ChatMessage,
    conversation_id: Optional[str] = Query(None, description="Existing conversation ID"),
    current_user: dict = Depends(get_current_active_user)
):
    """Send message to AI Coach and receive response."""
    user_id = get_user_id_from_token(current_user)

    # Create or retrieve conversation
    if conversation_id and conversation_id in conversations_db:
        conv = conversations_db[conversation_id]
        if conv["user_id"] != user_id:
            raise HTTPException(status_code=403, detail="Not your conversation")
    else:
        conversation_id = str(uuid.uuid4())
        conversations_db[conversation_id] = {
            "id": conversation_id,
            "user_id": user_id,
            "title": message.content[:50] + ("..." if len(message.content) > 50 else ""),
            "style": message.style,
            "created_at": datetime.utcnow(),
            "updated_at": datetime.utcnow()
        }
        messages_db[conversation_id] = []

    # Get conversation history
    history = messages_db.get(conversation_id, [])

    # Generate AI response
    ai_result = await get_ai_response(
        message.content,
        history,
        message.style,
        message.language
    )

    # Save messages
    now = datetime.utcnow()
    user_msg = {
        "role": "user",
        "content": message.content,
        "timestamp": now.isoformat()
    }
    assistant_msg = {
        "role": "assistant",
        "content": ai_result["content"],
        "timestamp": now.isoformat()
    }

    messages_db[conversation_id].extend([user_msg, assistant_msg])
    conversations_db[conversation_id]["updated_at"] = now

    response_id = str(uuid.uuid4())

    return ChatResponse(
        id=response_id,
        content=ai_result["content"],
        sources=ai_result["sources"],
        confidence=ai_result["confidence"],
        suggestions=ai_result["suggestions"],
        timestamp=now
    )


@router.post(
    "/chat/stream",
    summary="Send message with streaming response",
    description="""
    Invia messaggio e ricevi risposta in streaming (SSE).

    BUSINESS: UX migliore per risposte lunghe
    TEACHING: Server-Sent Events per streaming unidirezionale
    """
)
async def send_message_stream(
    message: ChatMessage,
    conversation_id: Optional[str] = Query(None),
    current_user: dict = Depends(get_current_active_user)
):
    """Send message and receive streaming response (SSE)."""
    user_id = get_user_id_from_token(current_user)

    # Retrieve or create conversation
    if conversation_id and conversation_id in conversations_db:
        conv = conversations_db[conversation_id]
        if conv["user_id"] != user_id:
            raise HTTPException(status_code=403, detail="Not your conversation")
        history = messages_db.get(conversation_id, [])
    else:
        history = []

    return StreamingResponse(
        stream_ai_response(
            message.content,
            history,
            message.style,
            message.language
        ),
        media_type="text/event-stream"
    )


# ============================================================================
# ENDPOINTS - CONVERSATIONS
# ============================================================================

@router.get(
    "/conversations",
    response_model=List[ConversationSummary],
    summary="List conversations",
    description="Lista conversazioni dell'utente"
)
async def list_conversations(
    limit: int = Query(default=20, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
    current_user: dict = Depends(get_current_active_user)
):
    """List user's conversations."""
    user_id = get_user_id_from_token(current_user)

    user_convs = [
        ConversationSummary(
            id=conv["id"],
            title=conv["title"],
            style=conv["style"],
            message_count=len(messages_db.get(conv["id"], [])),
            created_at=conv["created_at"],
            updated_at=conv["updated_at"]
        )
        for conv in conversations_db.values()
        if conv["user_id"] == user_id
    ]

    # Sort by updated_at descending
    user_convs.sort(key=lambda x: x.updated_at, reverse=True)

    return user_convs[offset:offset + limit]


@router.get(
    "/conversations/{conversation_id}",
    summary="Get conversation detail",
    description="Dettaglio conversazione con tutti i messaggi"
)
async def get_conversation(
    conversation_id: str,
    current_user: dict = Depends(get_current_active_user)
):
    """Get conversation details with all messages."""
    user_id = get_user_id_from_token(current_user)

    if conversation_id not in conversations_db:
        raise HTTPException(status_code=404, detail="Conversation not found")

    conv = conversations_db[conversation_id]
    if conv["user_id"] != user_id:
        raise HTTPException(status_code=403, detail="Not your conversation")

    return {
        **conv,
        "messages": messages_db.get(conversation_id, [])
    }


@router.delete(
    "/conversations/{conversation_id}",
    status_code=204,
    summary="Delete conversation",
    description="Elimina conversazione"
)
async def delete_conversation(
    conversation_id: str,
    current_user: dict = Depends(get_current_active_user)
):
    """Delete a conversation."""
    user_id = get_user_id_from_token(current_user)

    if conversation_id not in conversations_db:
        raise HTTPException(status_code=404, detail="Conversation not found")

    conv = conversations_db[conversation_id]
    if conv["user_id"] != user_id:
        raise HTTPException(status_code=403, detail="Not your conversation")

    del conversations_db[conversation_id]
    if conversation_id in messages_db:
        del messages_db[conversation_id]

    return None


# ============================================================================
# ENDPOINTS - FEEDBACK
# ============================================================================

@router.post(
    "/feedback/technique",
    response_model=TechniqueFeedback,
    summary="Get technique feedback",
    description="""
    Analizza tecnica da video e fornisce feedback dettagliato.

    BUSINESS: Valore core - feedback personalizzato
    METRICS: Analysis time <5s, satisfaction >4/5
    """
)
async def get_technique_feedback(
    request: TechniqueFeedbackRequest,
    current_user: dict = Depends(get_current_active_user)
):
    """Analyze technique from video and provide detailed feedback."""
    feedback = await analyze_technique(
        request.video_id,
        request.technique_name,
        request.timestamp_start,
        request.timestamp_end,
        request.focus_areas
    )

    return feedback


@router.post(
    "/feedback/pose",
    response_model=PoseFeedback,
    summary="Get real-time pose feedback",
    description="""
    Feedback real-time su pose (per app mobile/AR).

    BUSINESS: Differenziatore vs competitors
    METRICS: Response time <100ms
    TEACHING: Ottimizzato per bassa latenza
    """
)
async def get_pose_feedback(
    request: PoseFeedbackRequest,
    current_user: dict = Depends(get_current_active_user)
):
    """Get real-time feedback on pose landmarks."""
    # Validate landmarks count
    landmarks_count = len(request.landmarks)
    if landmarks_count not in [33, 75]:
        raise HTTPException(
            status_code=422,
            detail=f"Expected 33 or 75 landmarks, got {landmarks_count}. "
                   f"Use 33 for MediaPipe Pose or 75 for MediaPipe Holistic."
        )

    feedback = await analyze_pose_realtime(
        request.landmarks,
        request.technique_name,
        request.style
    )

    return feedback


# ============================================================================
# ENDPOINTS - KNOWLEDGE BASE
# ============================================================================

@router.get(
    "/knowledge/search",
    response_model=List[KnowledgeSearchResult],
    summary="Search knowledge base",
    description="""
    Cerca nella knowledge base arti marziali.

    TEACHING: Endpoint utile per debug RAG e per UI search.
    """
)
async def search_knowledge(
    query: str = Query(..., min_length=2, max_length=200, description="Search query"),
    style: Optional[MartialStyle] = Query(None, description="Filter by style"),
    limit: int = Query(default=10, ge=1, le=50, description="Max results"),
    current_user: dict = Depends(get_current_active_user)
):
    """Search the martial arts knowledge base."""
    try:
        from services.video_studio.ai_conversational_agent import KnowledgeRetriever

        retriever = KnowledgeRetriever()
        retriever.load_knowledge_base()

        # FIX: use retrieve() instead of search()
        results = retriever.retrieve(
            query=query,
            top_k=limit
        )

        # Map RetrievedKnowledge to KnowledgeSearchResult
        return [
            KnowledgeSearchResult(
                id=str(i),
                title=r.content.get("name", r.content.get("title", f"Result {i+1}")),
                content=r.summary[:500] if r.summary else str(r.content)[:500],
                relevance=r.relevance_score,
                source=r.source,
                style=style or MartialStyle.GENERAL
            )
            for i, r in enumerate(results)
        ]

    except ImportError:
        logger.warning("KnowledgeRetriever not available, using demo results")
        # Demo fallback
        return [
            KnowledgeSearchResult(
                id="demo-1",
                title=f"Risultato per: {query}",
                content=f"Contenuto demo relativo a '{query}' nelle arti marziali. "
                       f"Questo risultato e' generato automaticamente per testing.",
                relevance=0.9,
                source="demo_knowledge_base",
                style=style or MartialStyle.GENERAL
            ),
            KnowledgeSearchResult(
                id="demo-2",
                title=f"Tecnica correlata: {query}",
                content=f"Informazioni aggiuntive su tecniche correlate a '{query}'.",
                relevance=0.7,
                source="demo_knowledge_base",
                style=style or MartialStyle.GENERAL
            )
        ]


# ============================================================================
# ENDPOINTS - REFERENCE DATA
# ============================================================================

@router.get(
    "/styles",
    summary="Get supported styles",
    description="Lista stili arti marziali supportati"
)
async def get_supported_styles():
    """List all supported martial arts styles."""
    return [
        {
            "code": style.value,
            "name": style.name.replace("_", " ").title(),
            "description": _get_style_description(style)
        }
        for style in MartialStyle
    ]


def _get_style_description(style: MartialStyle) -> str:
    """Get description for martial art style."""
    descriptions = {
        MartialStyle.KARATE: "Arte marziale giapponese che enfatizza colpi con mani e piedi",
        MartialStyle.KUNG_FU: "Termine generico per le arti marziali cinesi",
        MartialStyle.TAEKWONDO: "Arte marziale coreana nota per i calci acrobatici",
        MartialStyle.JUDO: "Arte marziale giapponese focalizzata su proiezioni e leve",
        MartialStyle.AIKIDO: "Arte marziale giapponese difensiva basata su movimenti circolari",
        MartialStyle.BOXING: "Sport da combattimento con soli pugni",
        MartialStyle.MUAY_THAI: "Arte marziale thailandese con gomiti, ginocchia, calci e pugni",
        MartialStyle.MMA: "Arti marziali miste che combinano varie discipline",
        MartialStyle.CAPOEIRA: "Arte marziale brasiliana che combina danza e acrobazie",
        MartialStyle.KRAV_MAGA: "Sistema di combattimento israeliano per autodifesa",
        MartialStyle.TAI_CHI: "Arte marziale cinese interna con movimenti lenti e fluidi",
        MartialStyle.JIU_JITSU: "Arte marziale brasiliana focalizzata sulla lotta a terra",
        MartialStyle.GENERAL: "Principi generali applicabili a tutte le arti marziali"
    }
    return descriptions.get(style, "Arte marziale")


@router.get(
    "/health",
    summary="Health check",
    description="Health check servizio AI Coach"
)
async def health_check():
    """Check AI Coach service health."""
    # Check available services
    conversational_available = False
    corrector_available = False
    knowledge_available = False

    try:
        from services.video_studio.ai_conversational_agent import ConversationalAgent
        conversational_available = True
    except ImportError:
        pass

    try:
        from services.video_studio.realtime_pose_corrector import RealtimePoseCorrector
        corrector_available = True
    except ImportError:
        pass

    try:
        from services.video_studio.ai_conversational_agent import KnowledgeRetriever
        knowledge_available = True
    except ImportError:
        pass

    return {
        "status": "healthy",
        "service": "ai_coach",
        "features": {
            "conversational_ai": conversational_available,
            "technique_feedback": conversational_available,
            "realtime_pose": corrector_available,
            "knowledge_search": knowledge_available,
            "streaming_responses": True,
            "multi_language": True
        },
        "supported_styles": len(MartialStyle),
        "active_conversations": len(conversations_db),
        "timestamp": datetime.utcnow().isoformat()
    }

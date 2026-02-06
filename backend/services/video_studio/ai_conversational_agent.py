"""
AI Conversational Agent - Martial Arts Expert
==============================================

🎯 BUSINESS VALUE:
- Differentiation vs competitors
- Premium tier feature (subscription)
- 24/7 expert available
- Personalized teaching strategies
- Multi-language support

🔧 TECHNICAL:
- RAG (Retrieval-Augmented Generation) su knowledge base
- LLM integration (GPT-4 / Claude / Llama)
- Context management per conversazioni lunghe
- Voice interface ready (speech-to-text + text-to-speech)
- Caching intelligente per ridurre API costs

📊 METRICS:
- Response time: <2s per risposta
- Accuracy: >90% su termini tecnici
- Context retention: 10+ messaggi
- Cost: <$0.01 per conversazione

🏗️ ARCHITECTURE:
- INPUT: user question (text or voice)
- PROCESS: RAG retrieval → LLM reasoning → response generation
- OUTPUT: expert answer (text or audio)
- DEPENDENCIES: knowledge_extractor.py, hybrid_translator.py, OpenAI/Anthropic API
"""

import os
import json
import logging
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field, asdict
from datetime import datetime
import time
from collections import deque
import hashlib

# Try OpenAI first, fallback to local implementation
try:
    import openai
    OPENAI_AVAILABLE = True
except ImportError:
    OPENAI_AVAILABLE = False
    logging.warning("OpenAI not available. Install with: pip install openai")

# Try Anthropic
try:
    import anthropic
    ANTHROPIC_AVAILABLE = True
except ImportError:
    ANTHROPIC_AVAILABLE = False
    logging.warning("Anthropic not available. Install with: pip install anthropic")

# Try speech recognition (STT)
try:
    import speech_recognition as sr
    STT_AVAILABLE = True
except ImportError:
    STT_AVAILABLE = False
    logging.warning("Speech recognition not available. Install with: pip install SpeechRecognition")

# Try TTS (multiple backends)
try:
    import pyttsx3
    TTS_PYTTSX3_AVAILABLE = True
except ImportError:
    TTS_PYTTSX3_AVAILABLE = False

try:
    from gtts import gTTS
    TTS_GTTS_AVAILABLE = True
except ImportError:
    TTS_GTTS_AVAILABLE = False

if not TTS_PYTTSX3_AVAILABLE and not TTS_GTTS_AVAILABLE:
    logging.warning("TTS not available. Install with: pip install pyttsx3 OR pip install gTTS")

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@dataclass
class Message:
    """Single message in conversation"""
    role: str  # "user", "assistant", "system"
    content: str
    timestamp: datetime = field(default_factory=datetime.now)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ConversationContext:
    """Context per conversazione"""
    conversation_id: str
    messages: List[Message] = field(default_factory=list)
    user_level: str = "beginner"  # "beginner", "intermediate", "advanced", "expert"
    user_style: Optional[str] = None  # "karate", "tai_chi", etc.
    user_goals: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class RetrievedKnowledge:
    """Knowledge retrieved from RAG"""
    source: str  # "form", "sequence", "pattern", "technique"
    content: Dict[str, Any]
    relevance_score: float  # 0-1
    summary: str


class KnowledgeRetriever:
    """
    Retrieve relevant knowledge from extracted knowledge base

    🎯 RETRIEVAL STRATEGY:
    1. Keyword matching (tecniche, stili, movimenti)
    2. Semantic search (embeddings - optional)
    3. Ranking by relevance + recency
    4. Top-K selection (default k=5)
    """

    def __init__(self, knowledge_base_path: Optional[Path] = None):
        """
        Args:
            knowledge_base_path: Path to JSON knowledge base
        """
        self.knowledge_base_path = knowledge_base_path
        self.forms_db: List[Dict] = []
        self.sequences_db: List[Dict] = []
        self.patterns_db: List[Dict] = []

        # Keyword index per fast lookup
        self.keyword_index: Dict[str, List[int]] = {}

        # Cache per queries recenti
        self.cache: Dict[str, List[RetrievedKnowledge]] = {}
        self.cache_max_size = 100

        logger.info("KnowledgeRetriever initialized")

    def load_knowledge_base(self) -> bool:
        """Load knowledge base from JSON"""
        if not self.knowledge_base_path or not self.knowledge_base_path.exists():
            logger.warning("Knowledge base not found, using empty database")
            return False

        try:
            with open(self.knowledge_base_path, 'r', encoding='utf-8') as f:
                data = json.load(f)

            self.forms_db = data.get('forms', [])
            self.sequences_db = data.get('sequences', [])
            self.patterns_db = data.get('patterns', [])

            # Build keyword index
            self._build_keyword_index()

            logger.info(f"Loaded {len(self.forms_db)} forms, "
                       f"{len(self.sequences_db)} sequences, "
                       f"{len(self.patterns_db)} patterns")
            return True

        except Exception as e:
            logger.error(f"Failed to load knowledge base: {e}")
            return False

    def _build_keyword_index(self):
        """Build inverted index for fast keyword lookup"""
        # Index forms
        for idx, form in enumerate(self.forms_db):
            keywords = self._extract_keywords(form)
            for keyword in keywords:
                if keyword not in self.keyword_index:
                    self.keyword_index[keyword] = []
                self.keyword_index[keyword].append(('form', idx))

        # Index sequences
        for idx, sequence in enumerate(self.sequences_db):
            keywords = self._extract_keywords(sequence)
            for keyword in keywords:
                if keyword not in self.keyword_index:
                    self.keyword_index[keyword] = []
                self.keyword_index[keyword].append(('sequence', idx))

        logger.info(f"Built keyword index with {len(self.keyword_index)} unique keywords")

    def _extract_keywords(self, item: Dict) -> List[str]:
        """Extract keywords from knowledge item"""
        keywords = []

        # Name
        if 'name' in item:
            keywords.extend(item['name'].lower().split('_'))

        # Style
        if 'style' in item:
            keywords.append(item['style'].lower())

        # Techniques
        if 'techniques' in item:
            keywords.extend([t.lower() for t in item['techniques']])

        # Keywords array (explicit keywords from JSON)
        if 'keywords' in item:
            keywords.extend([k.lower().strip() for k in item['keywords']])

        return list(set(keywords))

    def retrieve(
        self,
        query: str,
        top_k: int = 5,
        min_relevance: float = 0.3
    ) -> List[RetrievedKnowledge]:
        """
        Retrieve relevant knowledge for query

        Args:
            query: User question
            top_k: Number of results to return
            min_relevance: Minimum relevance score (0-1)

        Returns:
            List of RetrievedKnowledge sorted by relevance
        """
        # Check cache
        cache_key = self._get_cache_key(query, top_k)
        if cache_key in self.cache:
            logger.debug("Cache hit for query")
            return self.cache[cache_key]

        # Extract query keywords
        query_keywords = query.lower().split()

        # Retrieve candidates
        candidates = []

        # Keyword matching
        for keyword in query_keywords:
            if keyword in self.keyword_index:
                for source_type, idx in self.keyword_index[keyword]:
                    if source_type == 'form':
                        item = self.forms_db[idx]
                    elif source_type == 'sequence':
                        item = self.sequences_db[idx]
                    else:
                        continue

                    # Calculate relevance score
                    relevance = self._calculate_relevance(query_keywords, item)

                    if relevance >= min_relevance:
                        summary = self._generate_summary(item, source_type)

                        retrieved = RetrievedKnowledge(
                            source=source_type,
                            content=item,
                            relevance_score=relevance,
                            summary=summary
                        )
                        candidates.append(retrieved)

        # Deduplicate and sort
        candidates = self._deduplicate(candidates)
        candidates.sort(key=lambda x: x.relevance_score, reverse=True)

        # Select top-k
        results = candidates[:top_k]

        # Cache results
        if len(self.cache) >= self.cache_max_size:
            # Remove oldest entry
            self.cache.pop(next(iter(self.cache)))
        self.cache[cache_key] = results

        logger.info(f"Retrieved {len(results)} knowledge items for query")
        return results

    def _calculate_relevance(self, query_keywords: List[str], item: Dict) -> float:
        """Calculate relevance score (0-1)"""
        item_keywords = self._extract_keywords(item)

        # Partial matching (più permissivo)
        matches = 0
        for q_kw in query_keywords:
            for i_kw in item_keywords:
                # Match parziale (substring)
                if q_kw in i_kw or i_kw in q_kw:
                    matches += 1
                    break

        if len(query_keywords) == 0:
            return 0.0

        # Score based on percentage of query keywords matched
        return matches / len(query_keywords)

    def _generate_summary(self, item: Dict, source_type: str) -> str:
        """Generate human-readable summary"""
        if source_type == 'form':
            name = item.get('name', 'Unknown')
            style = item.get('style', 'generic')
            duration = item.get('duration', 0)
            return f"Forma '{name}' ({style}) - durata {duration:.0f}s"

        elif source_type == 'sequence':
            name = item.get('name', 'Unknown')
            techniques = item.get('techniques', [])
            return f"Sequenza '{name}' con tecniche: {', '.join(techniques[:3])}"

        return str(item)

    def _deduplicate(self, candidates: List[RetrievedKnowledge]) -> List[RetrievedKnowledge]:
        """Remove duplicate entries"""
        seen = set()
        unique = []

        for candidate in candidates:
            # Use content hash as identifier
            content_str = json.dumps(candidate.content, sort_keys=True)
            content_hash = hashlib.md5(content_str.encode()).hexdigest()

            if content_hash not in seen:
                seen.add(content_hash)
                unique.append(candidate)

        return unique

    def _get_cache_key(self, query: str, top_k: int) -> str:
        """Generate cache key"""
        return hashlib.md5(f"{query}_{top_k}".encode()).hexdigest()


class LLMInterface:
    """
    Interface for LLM APIs (OpenAI, Anthropic, local models)

    🎯 STRATEGY:
    - Try OpenAI GPT-4 first (best quality)
    - Fallback to Anthropic Claude (great for reasoning)
    - Fallback to local model (privacy + no cost)
    - Fallback to rule-based (no API available)
    """

    def __init__(
        self,
        provider: str = "openai",  # "openai", "anthropic", "local"
        model: str = "gpt-4",
        api_key: Optional[str] = None,
        max_tokens: int = 500,
        temperature: float = 0.7
    ):
        """
        Args:
            provider: LLM provider to use
            model: Model name
            api_key: API key (or None to use env var)
            max_tokens: Max response length
            temperature: Creativity (0-1)
        """
        self.provider = provider
        self.model = model
        self.max_tokens = max_tokens
        self.temperature = temperature

        # Initialize API client
        self.client = None

        if provider == "openai" and OPENAI_AVAILABLE:
            # Check if API key is available before initializing
            api_key_to_use = api_key or os.getenv('OPENAI_API_KEY')
            if api_key_to_use:
                try:
                    self.client = openai.OpenAI(api_key=api_key_to_use)
                except Exception as e:
                    logger.warning(f"Failed to initialize OpenAI client: {e}")
            else:
                logger.warning("OpenAI API key not provided, using fallback")

        elif provider == "anthropic" and ANTHROPIC_AVAILABLE:
            # Check if API key is available before initializing
            api_key_to_use = api_key or os.getenv('ANTHROPIC_API_KEY')
            if api_key_to_use:
                try:
                    self.client = anthropic.Anthropic(api_key=api_key_to_use)
                except Exception as e:
                    logger.warning(f"Failed to initialize Anthropic client: {e}")
            else:
                logger.warning("Anthropic API key not provided, using fallback")
        else:
            logger.warning(f"Provider '{provider}' not available, using fallback")

        # Stats
        self.total_calls = 0
        self.total_tokens = 0
        self.total_cost = 0.0

        logger.info(f"LLMInterface initialized: {provider}/{model}")

    def generate_response(
        self,
        messages: List[Dict[str, str]],
        system_prompt: Optional[str] = None
    ) -> Tuple[str, Dict[str, Any]]:
        """
        Generate response from LLM

        Args:
            messages: Conversation history [{"role": "user", "content": "..."}]
            system_prompt: Optional system prompt

        Returns:
            (response_text, metadata) tuple
        """
        start_time = time.time()

        # Add system prompt if provided
        if system_prompt:
            messages = [{"role": "system", "content": system_prompt}] + messages

        try:
            if self.provider == "openai" and self.client:
                response = self._call_openai(messages)
            elif self.provider == "anthropic" and self.client:
                response = self._call_anthropic(messages)
            else:
                # Fallback to rule-based
                response = self._fallback_response(messages)

            elapsed = time.time() - start_time

            # Update stats
            self.total_calls += 1
            self.total_tokens += response.get('tokens', 0)
            self.total_cost += response.get('cost', 0.0)

            metadata = {
                'provider': self.provider,
                'model': self.model,
                'tokens': response.get('tokens', 0),
                'cost': response.get('cost', 0.0),
                'latency_ms': elapsed * 1000
            }

            return response['text'], metadata

        except Exception as e:
            logger.error(f"LLM generation failed: {e}")
            fallback = self._fallback_response(messages)
            return fallback['text'], {'error': str(e)}

    def _call_openai(self, messages: List[Dict]) -> Dict:
        """Call OpenAI API"""
        response = self.client.chat.completions.create(
            model=self.model,
            messages=messages,
            max_tokens=self.max_tokens,
            temperature=self.temperature
        )

        tokens = response.usage.total_tokens
        cost = self._estimate_cost_openai(tokens)

        return {
            'text': response.choices[0].message.content,
            'tokens': tokens,
            'cost': cost
        }

    def _call_anthropic(self, messages: List[Dict]) -> Dict:
        """Call Anthropic API"""
        # Anthropic uses slightly different format
        system_msg = next((m['content'] for m in messages if m['role'] == 'system'), None)
        user_messages = [m for m in messages if m['role'] != 'system']

        response = self.client.messages.create(
            model=self.model,
            max_tokens=self.max_tokens,
            temperature=self.temperature,
            system=system_msg or "",
            messages=user_messages
        )

        tokens = response.usage.input_tokens + response.usage.output_tokens
        cost = self._estimate_cost_anthropic(tokens)

        return {
            'text': response.content[0].text,
            'tokens': tokens,
            'cost': cost
        }

    def _fallback_response(self, messages: List[Dict]) -> Dict:
        """Rule-based fallback when no LLM available"""
        last_user_message = next((m['content'] for m in reversed(messages) if m['role'] == 'user'), "")

        response = (
            "Mi dispiace, al momento non posso accedere al sistema AI principale. "
            "Tuttavia, posso darti alcune indicazioni generali:\n\n"
        )

        # Simple keyword matching for common questions
        lower_msg = last_user_message.lower()

        if any(word in lower_msg for word in ['punch', 'pugno', 'colpire']):
            response += (
                "Per un pugno efficace:\n"
                "1. Ruota i fianchi per generare potenza\n"
                "2. Mantieni il gomito vicino al corpo\n"
                "3. Estendi completamente il braccio\n"
                "4. Ritorna velocemente in guardia"
            )
        elif any(word in lower_msg for word in ['stance', 'posizione', 'guardia']):
            response += (
                "Per una posizione stabile:\n"
                "1. Piedi alla larghezza delle spalle\n"
                "2. Ginocchia leggermente piegate\n"
                "3. Peso distribuito equamente\n"
                "4. Centro di gravità basso"
            )
        elif any(word in lower_msg for word in ['kick', 'calcio']):
            response += (
                "Per un calcio efficace:\n"
                "1. Solleva il ginocchio prima\n"
                "2. Estendi la gamba velocemente\n"
                "3. Colpisci con la parte corretta del piede\n"
                "4. Ritorna in posizione controllata"
            )
        else:
            response += (
                "Ti consiglio di:\n"
                "1. Praticare lentamente all'inizio\n"
                "2. Focalizzarti sulla forma corretta\n"
                "3. Gradualmente aumentare la velocità\n"
                "4. Chiedere feedback a un istruttore"
            )

        return {
            'text': response,
            'tokens': 0,
            'cost': 0.0
        }

    def _estimate_cost_openai(self, tokens: int) -> float:
        """Estimate OpenAI API cost"""
        # GPT-4: ~$0.03 per 1K tokens (average input + output)
        if 'gpt-4' in self.model:
            return tokens * 0.03 / 1000
        # GPT-3.5: ~$0.002 per 1K tokens
        else:
            return tokens * 0.002 / 1000

    def _estimate_cost_anthropic(self, tokens: int) -> float:
        """Estimate Anthropic API cost"""
        # Claude: ~$0.015 per 1K tokens
        return tokens * 0.015 / 1000


class ConversationalAgent:
    """
    Main AI Conversational Agent

    🎯 CONVERSATION FLOW:
    1. User asks question
    2. Retrieve relevant knowledge (RAG)
    3. Build context (conversation history + retrieved knowledge)
    4. Generate response (LLM)
    5. Store in conversation history
    6. Return response to user
    """

    # System prompt template
    SYSTEM_PROMPT = """Sei un esperto di arti marziali con 20+ anni di esperienza in stili multipli.

Il tuo ruolo è:
- Rispondere a domande su tecniche, forme, e applicazioni
- Adattare le spiegazioni al livello dell'utente ({user_level})
- Usare la knowledge base fornita per risposte accurate
- Essere paziente, incoraggiante e costruttivo
- Correggere errori comuni gentilmente

Stile di risposta:
- Chiaro e conciso (2-4 frasi quando possibile)
- Esempi pratici quando utile
- Enfasi su sicurezza e forma corretta
- Riferimenti alla knowledge base quando disponibile

Knowledge base disponibile:
{knowledge_context}

Conversazione corrente:
{conversation_history}
"""

    def __init__(
        self,
        knowledge_base_path: Optional[Path] = None,
        llm_provider: str = "openai",
        llm_model: str = "gpt-4",
        api_key: Optional[str] = None,
        enable_voice: bool = False
    ):
        """
        Args:
            knowledge_base_path: Path to knowledge base JSON
            llm_provider: LLM provider ("openai", "anthropic", "local")
            llm_model: Model name
            api_key: API key for LLM
            enable_voice: Enable voice interface (requires STT/TTS)
        """
        self.knowledge_base_path = knowledge_base_path
        self.enable_voice = enable_voice

        # Components
        self.retriever = KnowledgeRetriever(knowledge_base_path)

        # Load knowledge base automatically if path provided
        if knowledge_base_path:
            loaded = self.retriever.load_knowledge_base()
            if loaded:
                logger.info(f"Knowledge base loaded successfully from {knowledge_base_path}")
            else:
                logger.warning(f"Failed to load knowledge base from {knowledge_base_path}")

        self.llm = LLMInterface(llm_provider, llm_model, api_key)

        # Conversations
        self.conversations: Dict[str, ConversationContext] = {}
        self.active_conversation_id: Optional[str] = None

        # Stats
        self.total_conversations = 0
        self.total_messages = 0

        logger.info("ConversationalAgent initialized")

    def start_conversation(
        self,
        user_level: str = "beginner",
        user_style: Optional[str] = None,
        user_goals: Optional[List[str]] = None
    ) -> str:
        """
        Start a new conversation

        Args:
            user_level: User skill level
            user_style: Preferred martial arts style
            user_goals: User learning goals

        Returns:
            conversation_id
        """
        conversation_id = f"conv_{int(time.time())}_{self.total_conversations}"

        context = ConversationContext(
            conversation_id=conversation_id,
            user_level=user_level,
            user_style=user_style,
            user_goals=user_goals or []
        )

        self.conversations[conversation_id] = context
        self.active_conversation_id = conversation_id
        self.total_conversations += 1

        logger.info(f"Started conversation {conversation_id}")
        return conversation_id

    def ask(
        self,
        question: str,
        conversation_id: Optional[str] = None
    ) -> Tuple[str, Dict[str, Any]]:
        """
        Ask a question and get response

        Args:
            question: User question
            conversation_id: Optional conversation ID (uses active if not provided)

        Returns:
            (response, metadata) tuple
        """
        # Get or create conversation
        if conversation_id is None:
            conversation_id = self.active_conversation_id

        if conversation_id is None or conversation_id not in self.conversations:
            # Auto-create conversation
            conversation_id = self.start_conversation()

        context = self.conversations[conversation_id]

        # Add user message
        user_message = Message(role="user", content=question)
        context.messages.append(user_message)

        # Retrieve relevant knowledge
        retrieved = self.retriever.retrieve(question, top_k=3)

        # Build knowledge context
        knowledge_context = self._format_knowledge_context(retrieved)

        # Build conversation history
        conversation_history = self._format_conversation_history(context.messages[-5:])  # Last 5 messages

        # Generate system prompt
        system_prompt = self.SYSTEM_PROMPT.format(
            user_level=context.user_level,
            knowledge_context=knowledge_context,
            conversation_history=conversation_history
        )

        # Prepare messages for LLM
        llm_messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": question}
        ]

        # Generate response
        response_text, llm_metadata = self.llm.generate_response(llm_messages)

        # Add assistant message
        assistant_message = Message(
            role="assistant",
            content=response_text,
            metadata=llm_metadata
        )
        context.messages.append(assistant_message)

        self.total_messages += 2  # user + assistant

        # Prepare response metadata
        metadata = {
            'conversation_id': conversation_id,
            'retrieved_knowledge': [r.summary for r in retrieved],
            'llm_metadata': llm_metadata
        }

        logger.info(f"Generated response for conversation {conversation_id}")
        return response_text, metadata

    def _format_knowledge_context(self, retrieved: List[RetrievedKnowledge]) -> str:
        """Format retrieved knowledge for system prompt"""
        if not retrieved:
            return "Nessuna knowledge base specifica disponibile."

        context_parts = []

        for item in retrieved:
            context_parts.append(f"- {item.summary} (relevance: {item.relevance_score:.2f})")

        return "\n".join(context_parts)

    def _format_conversation_history(self, messages: List[Message]) -> str:
        """Format conversation history for system prompt"""
        if not messages:
            return "Nuova conversazione."

        history_parts = []

        for msg in messages:
            role = "Utente" if msg.role == "user" else "Assistente"
            history_parts.append(f"{role}: {msg.content[:100]}")  # Truncate long messages

        return "\n".join(history_parts)

    def get_conversation_history(
        self,
        conversation_id: Optional[str] = None
    ) -> List[Message]:
        """Get conversation history"""
        if conversation_id is None:
            conversation_id = self.active_conversation_id

        if conversation_id not in self.conversations:
            return []

        return self.conversations[conversation_id].messages

    def export_conversation(
        self,
        conversation_id: str,
        output_path: Path
    ) -> bool:
        """Export conversation to JSON"""
        if conversation_id not in self.conversations:
            logger.error(f"Conversation {conversation_id} not found")
            return False

        try:
            context = self.conversations[conversation_id]

            export_data = {
                'conversation_id': context.conversation_id,
                'user_level': context.user_level,
                'user_style': context.user_style,
                'user_goals': context.user_goals,
                'messages': [
                    {
                        'role': m.role,
                        'content': m.content,
                        'timestamp': m.timestamp.isoformat(),
                        'metadata': m.metadata
                    }
                    for m in context.messages
                ]
            }

            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(export_data, f, indent=2, ensure_ascii=False)

            logger.info(f"Exported conversation to {output_path}")
            return True

        except Exception as e:
            logger.error(f"Failed to export conversation: {e}")
            return False

    def get_stats(self) -> Dict[str, Any]:
        """Get agent statistics"""
        return {
            'total_conversations': self.total_conversations,
            'active_conversations': len(self.conversations),
            'total_messages': self.total_messages,
            'llm_total_calls': self.llm.total_calls,
            'llm_total_tokens': self.llm.total_tokens,
            'llm_total_cost': self.llm.total_cost
        }


class VoiceInterface:
    """
    Voice interface per STT (Speech-to-Text) e TTS (Text-to-Speech)

    🎯 BACKENDS SUPPORTATI:
    - STT: Google Speech Recognition (free), Whisper API
    - TTS: pyttsx3 (offline), gTTS (Google TTS), ElevenLabs API
    """

    def __init__(
        self,
        stt_backend: str = "google",  # "google", "whisper"
        tts_backend: str = "pyttsx3",  # "pyttsx3", "gtts", "elevenlabs"
        language: str = "it-IT"
    ):
        """
        Args:
            stt_backend: Speech-to-text backend
            tts_backend: Text-to-speech backend
            language: Language code (it-IT, en-US, etc.)
        """
        self.stt_backend = stt_backend
        self.tts_backend = tts_backend
        self.language = language

        # Initialize STT
        if STT_AVAILABLE:
            self.recognizer = sr.Recognizer()
            self.microphone = sr.Microphone()
            logger.info(f"STT initialized: {stt_backend}")
        else:
            self.recognizer = None
            self.microphone = None
            logger.warning("STT not available")

        # Initialize TTS
        if tts_backend == "pyttsx3" and TTS_PYTTSX3_AVAILABLE:
            self.tts_engine = pyttsx3.init()
            # Configure voice (Italian if available)
            voices = self.tts_engine.getProperty('voices')
            for voice in voices:
                if 'italian' in voice.name.lower() or 'it' in voice.languages:
                    self.tts_engine.setProperty('voice', voice.id)
                    break
            self.tts_engine.setProperty('rate', 150)  # Speed
            logger.info("TTS initialized: pyttsx3")
        else:
            self.tts_engine = None
            if not TTS_GTTS_AVAILABLE:
                logger.warning("TTS not available")

    def listen(self, timeout: int = 5, phrase_time_limit: int = 10) -> Optional[str]:
        """
        Listen to microphone and convert speech to text

        Args:
            timeout: Timeout for listening (seconds)
            phrase_time_limit: Max phrase duration (seconds)

        Returns:
            Recognized text or None
        """
        if not STT_AVAILABLE or not self.recognizer:
            logger.error("STT not available")
            return None

        try:
            with self.microphone as source:
                logger.info("Listening...")
                # Adjust for ambient noise
                self.recognizer.adjust_for_ambient_noise(source, duration=0.5)

                # Listen
                audio = self.recognizer.listen(
                    source,
                    timeout=timeout,
                    phrase_time_limit=phrase_time_limit
                )

            logger.info("Processing speech...")

            # Recognize speech
            if self.stt_backend == "google":
                text = self.recognizer.recognize_google(audio, language=self.language)
            elif self.stt_backend == "whisper":
                # Whisper API (requires openai package + API key)
                text = self.recognizer.recognize_whisper_api(audio, api_key=os.getenv('OPENAI_API_KEY'))
            else:
                text = self.recognizer.recognize_google(audio, language=self.language)

            logger.info(f"Recognized: {text}")
            return text

        except sr.WaitTimeoutError:
            logger.warning("Listening timeout")
            return None
        except sr.UnknownValueError:
            logger.warning("Could not understand audio")
            return None
        except sr.RequestError as e:
            logger.error(f"STT service error: {e}")
            return None
        except Exception as e:
            logger.error(f"STT error: {e}")
            return None

    def speak(self, text: str, save_to_file: Optional[Path] = None) -> bool:
        """
        Convert text to speech and play

        Args:
            text: Text to speak
            save_to_file: Optional path to save audio file

        Returns:
            Success status
        """
        try:
            if self.tts_backend == "pyttsx3" and self.tts_engine:
                # pyttsx3 (offline)
                if save_to_file:
                    self.tts_engine.save_to_file(text, str(save_to_file))
                    self.tts_engine.runAndWait()
                else:
                    self.tts_engine.say(text)
                    self.tts_engine.runAndWait()

                logger.info("Speech synthesis completed")
                return True

            elif self.tts_backend == "gtts" and TTS_GTTS_AVAILABLE:
                # Google TTS (requires internet)
                lang_code = self.language.split('-')[0]  # it-IT → it
                tts = gTTS(text=text, lang=lang_code, slow=False)

                if save_to_file:
                    tts.save(str(save_to_file))
                else:
                    # Save to temp file and play
                    import tempfile
                    import os
                    temp_file = tempfile.NamedTemporaryFile(delete=False, suffix='.mp3')
                    tts.save(temp_file.name)
                    temp_file.close()

                    # Play audio (requires system audio player)
                    if os.name == 'nt':  # Windows
                        os.system(f'start {temp_file.name}')
                    elif os.name == 'posix':  # Linux/Mac
                        os.system(f'mpg123 {temp_file.name}')

                    # Cleanup after delay
                    time.sleep(len(text) / 10)  # Rough estimate
                    try:
                        os.unlink(temp_file.name)
                    except:
                        pass

                logger.info("Speech synthesis completed")
                return True

            else:
                logger.error("No TTS backend available")
                return False

        except Exception as e:
            logger.error(f"TTS error: {e}")
            return False


# ==================== STANDALONE EXECUTION ====================

def main():
    """Main entry point for testing"""
    import argparse

    parser = argparse.ArgumentParser(description="AI Conversational Agent for Martial Arts")
    parser.add_argument('--knowledge-base', type=str, default=None,
                       help='Path to knowledge base JSON')
    parser.add_argument('--provider', type=str, default='openai',
                       choices=['openai', 'anthropic', 'local'],
                       help='LLM provider')
    parser.add_argument('--model', type=str, default='gpt-4',
                       help='LLM model name')
    parser.add_argument('--api-key', type=str, default=None,
                       help='API key (or use env var)')

    args = parser.parse_args()

    # Initialize agent
    kb_path = Path(args.knowledge_base) if args.knowledge_base else None

    agent = ConversationalAgent(
        knowledge_base_path=kb_path,
        llm_provider=args.provider,
        llm_model=args.model,
        api_key=args.api_key
    )

    # Load knowledge base
    if kb_path:
        agent.retriever.load_knowledge_base()

    # Start conversation
    print("AI Martial Arts Expert - Type 'quit' to exit, 'stats' for statistics")
    print("-" * 60)

    agent.start_conversation(user_level='beginner')

    while True:
        try:
            question = input("\nYou: ").strip()

            if not question:
                continue

            if question.lower() in ['quit', 'exit', 'q']:
                print("Goodbye!")
                break

            if question.lower() == 'stats':
                stats = agent.get_stats()
                print("\nStatistics:")
                for key, value in stats.items():
                    print(f"  {key}: {value}")
                continue

            # Get response
            response, metadata = agent.ask(question)

            print(f"\nAI: {response}")

            # Show retrieved knowledge
            if metadata.get('retrieved_knowledge'):
                print(f"\n[Retrieved: {', '.join(metadata['retrieved_knowledge'])}]")

        except KeyboardInterrupt:
            print("\nInterrupted. Goodbye!")
            break
        except Exception as e:
            print(f"\nError: {e}")
            logger.exception("Error in main loop")


if __name__ == '__main__':
    main()

"""
================================================================================
AI_MODULE: Grammar Rule Normalizer
AI_VERSION: 1.0.0
AI_DESCRIPTION: Riformulazione e anonimizzazione regole grammaticali
AI_BUSINESS: Rimozione tracce fonte, generazione nuovi esempi
AI_TEACHING: NLP, riformulazione, anonimizzazione, LLM prompting
AI_DEPENDENCIES: httpx (for Ollama)
AI_CREATED: 2026-02-05

LEGAL PRINCIPLE:
Grammar rules are FACTS, not copyrightable.
This module:
1. REFORMULATES descriptions (no direct quotes)
2. GENERATES NEW examples (not from source)
3. REMOVES ALL source references
4. ANONYMIZES everything

FORBIDDEN FIELDS (never stored):
- source, book, author, page, isbn, publisher, chapter
================================================================================
"""

import logging
import json
import uuid
import hashlib
import re
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, field, asdict
from datetime import datetime
from enum import Enum

logger = logging.getLogger(__name__)


class RuleCategory(str, Enum):
    """Categories of grammar rules."""
    PARTICLE = "particle"
    VERB_FORM = "verb_form"
    ADJECTIVE_FORM = "adjective_form"
    SENTENCE_PATTERN = "sentence_pattern"
    HONORIFIC = "honorific"
    CONJUNCTION = "conjunction"
    EXPRESSION = "expression"
    COUNTER = "counter"
    AUXILIARY = "auxiliary"
    CONDITIONAL = "conditional"
    CAUSATIVE = "causative"
    PASSIVE = "passive"
    QUOTATION = "quotation"
    NEGATION = "negation"
    QUESTION = "question"
    OTHER = "other"


class DifficultyLevel(str, Enum):
    """Difficulty levels (JLPT/HSK aligned)."""
    BASIC = "basic"           # N5 / HSK1
    ELEMENTARY = "elementary" # N4 / HSK2
    INTERMEDIATE = "intermediate"  # N3 / HSK3-4
    ADVANCED = "advanced"     # N2 / HSK5
    EXPERT = "expert"         # N1 / HSK6


@dataclass
class RuleExample:
    """An example sentence for a grammar rule."""
    original: str
    translation: str
    note: str = ""
    reading: str = ""  # Furigana/Pinyin


@dataclass
class NormalizedRule:
    """
    A normalized, anonymized grammar rule.

    IMPORTANT: No source information is stored!
    """
    id: str
    category: RuleCategory
    name: str
    description: str  # REFORMULATED, not quoted
    pattern: str
    examples: List[RuleExample]
    exceptions: List[str]
    difficulty: DifficultyLevel
    related_rules: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)
    created_at: str = ""

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "id": self.id,
            "category": self.category.value,
            "name": self.name,
            "description": self.description,
            "pattern": self.pattern,
            "examples": [
                {
                    "original": ex.original,
                    "translation": ex.translation,
                    "note": ex.note,
                    "reading": ex.reading
                }
                for ex in self.examples
            ],
            "exceptions": self.exceptions,
            "difficulty": self.difficulty.value,
            "related_rules": self.related_rules,
            "tags": self.tags,
            "created_at": self.created_at
        }


# Words that must NEVER appear in output
FORBIDDEN_WORDS = [
    "source", "book", "author", "page", "isbn", "publisher",
    "chapter", "edition", "copyright", "rights", "reserved",
    "textbook", "manual", "guide", "volume", "citation"
]


class RuleNormalizer:
    """
    Normalizes and anonymizes grammar rules extracted from text.

    Uses LLM to:
    1. Reformulate descriptions (avoid direct quotes)
    2. Generate NEW example sentences
    3. Classify difficulty and category
    4. Remove any source traces
    """

    # LLM config (Ollama)
    LLM_CONFIG = {
        "base_url": "http://localhost:11434",
        "model": "qwen2.5:14b",  # Good for CJK
        "temperature": 0.3,
        "num_ctx": 4096,
    }

    EXTRACTION_PROMPT = """You are a grammar expert. Extract grammar rules from the following text.

IMPORTANT RULES:
1. REFORMULATE all descriptions in your own words - do NOT quote the source
2. Generate NEW example sentences - do NOT copy examples from the text
3. Output ONLY valid JSON
4. Never include any source references

TEXT TO ANALYZE:
{text}

LANGUAGE: {language}

Extract grammar rules in this JSON format:
```json
[
  {{
    "name": "Rule name (e.g., Particella は)",
    "category": "particle|verb_form|sentence_pattern|etc",
    "description": "YOUR OWN reformulated explanation",
    "pattern": "[Structure pattern]",
    "examples": [
      {{"original": "NEW example sentence", "translation": "Translation", "note": "Optional note"}}
    ],
    "exceptions": ["Exception 1", "Exception 2"],
    "difficulty": "basic|elementary|intermediate|advanced|expert",
    "related_rules": ["related_rule_name"],
    "tags": ["tag1", "tag2"]
  }}
]
```

Return ONLY the JSON array, no other text."""

    def __init__(self, llm_base_url: Optional[str] = None):
        self.llm_base_url = llm_base_url or self.LLM_CONFIG["base_url"]
        self._httpx = None

    def _ensure_httpx(self):
        """Lazy import of httpx."""
        if self._httpx is None:
            try:
                import httpx
                self._httpx = httpx
            except ImportError:
                raise ImportError(
                    "httpx not installed. Run: pip install httpx"
                )
        return self._httpx

    async def extract_rules_from_text(
        self,
        text: str,
        language: str = "ja"
    ) -> List[NormalizedRule]:
        """
        Extract and normalize grammar rules from text using LLM.

        Args:
            text: Text chunk to analyze
            language: Target language (ja, zh, ko)

        Returns:
            List of normalized, anonymized rules
        """
        httpx = self._ensure_httpx()

        prompt = self.EXTRACTION_PROMPT.format(
            text=text[:8000],  # Limit to avoid context overflow
            language=language
        )

        try:
            async with httpx.AsyncClient(timeout=120.0) as client:
                response = await client.post(
                    f"{self.llm_base_url}/api/generate",
                    json={
                        "model": self.LLM_CONFIG["model"],
                        "prompt": prompt,
                        "stream": False,
                        "options": {
                            "temperature": self.LLM_CONFIG["temperature"],
                            "num_ctx": self.LLM_CONFIG["num_ctx"],
                        }
                    }
                )
                response.raise_for_status()
                result = response.json()
                llm_output = result.get("response", "")

        except Exception as e:
            logger.error(f"LLM call failed: {e}")
            return []

        # Parse LLM output
        rules = self._parse_llm_output(llm_output, language)

        # Verify anonymization
        for rule in rules:
            self._verify_no_source_traces(rule)

        return rules

    def _parse_llm_output(
        self,
        output: str,
        language: str
    ) -> List[NormalizedRule]:
        """Parse LLM JSON output into NormalizedRule objects."""
        # Extract JSON from output
        json_match = re.search(r'\[[\s\S]*\]', output)
        if not json_match:
            logger.warning("No JSON found in LLM output")
            return []

        try:
            data = json.loads(json_match.group())
        except json.JSONDecodeError as e:
            logger.warning(f"JSON parse error: {e}")
            return []

        rules = []
        for item in data:
            try:
                rule = self._create_rule_from_dict(item, language)
                if rule:
                    rules.append(rule)
            except Exception as e:
                logger.warning(f"Failed to create rule: {e}")
                continue

        return rules

    def _create_rule_from_dict(
        self,
        data: Dict[str, Any],
        language: str
    ) -> Optional[NormalizedRule]:
        """Create a NormalizedRule from parsed dict."""
        # Generate unique ID
        rule_id = self._generate_rule_id(
            data.get("name", ""),
            data.get("pattern", ""),
            language
        )

        # Parse category
        category_str = data.get("category", "other").lower()
        try:
            category = RuleCategory(category_str)
        except ValueError:
            category = RuleCategory.OTHER

        # Parse difficulty
        difficulty_str = data.get("difficulty", "intermediate").lower()
        try:
            difficulty = DifficultyLevel(difficulty_str)
        except ValueError:
            difficulty = DifficultyLevel.INTERMEDIATE

        # Parse examples
        examples = []
        for ex_data in data.get("examples", []):
            if isinstance(ex_data, dict):
                examples.append(RuleExample(
                    original=ex_data.get("original", ""),
                    translation=ex_data.get("translation", ""),
                    note=ex_data.get("note", ""),
                    reading=ex_data.get("reading", "")
                ))

        # Create rule
        rule = NormalizedRule(
            id=rule_id,
            category=category,
            name=data.get("name", "Unknown Rule"),
            description=data.get("description", ""),
            pattern=data.get("pattern", ""),
            examples=examples,
            exceptions=data.get("exceptions", []),
            difficulty=difficulty,
            related_rules=data.get("related_rules", []),
            tags=data.get("tags", []),
            created_at=datetime.utcnow().isoformat()
        )

        return rule

    def _generate_rule_id(
        self,
        name: str,
        pattern: str,
        language: str
    ) -> str:
        """Generate a unique, deterministic ID for a rule."""
        content = f"{language}:{name}:{pattern}"
        hash_val = hashlib.sha256(content.encode()).hexdigest()[:12]
        return f"rule_{language}_{hash_val}"

    def _verify_no_source_traces(self, rule: NormalizedRule) -> bool:
        """
        Verify that a rule contains no source traces.

        Raises ValueError if forbidden words are found.
        """
        # Convert to JSON for full text check
        json_str = json.dumps(rule.to_dict()).lower()

        for word in FORBIDDEN_WORDS:
            if word in json_str:
                logger.warning(
                    f"Forbidden word '{word}' found in rule {rule.id}, "
                    "attempting to clean..."
                )
                # Try to clean it
                self._clean_rule(rule)
                # Re-check
                json_str = json.dumps(rule.to_dict()).lower()
                if word in json_str:
                    raise ValueError(
                        f"Cannot remove '{word}' from rule {rule.id}"
                    )

        return True

    def _clean_rule(self, rule: NormalizedRule):
        """Remove any forbidden content from a rule."""
        # Clean description
        for word in FORBIDDEN_WORDS:
            pattern = re.compile(rf'\b{word}\b[^.]*\.?\s*', re.IGNORECASE)
            rule.description = pattern.sub('', rule.description)

        # Clean notes in examples
        for example in rule.examples:
            for word in FORBIDDEN_WORDS:
                pattern = re.compile(rf'\b{word}\b[^.]*\.?\s*', re.IGNORECASE)
                example.note = pattern.sub('', example.note)

    async def reformulate_description(
        self,
        original_description: str,
        language: str = "ja"
    ) -> str:
        """
        Reformulate a description to avoid direct quotes.

        Uses LLM to rewrite the description in different words.
        """
        httpx = self._ensure_httpx()

        prompt = f"""Reformulate this grammar explanation in your own words.
Keep the meaning but use different phrasing.
Do not reference any source.

Original: {original_description}

Language context: {language}

Reformulated:"""

        try:
            async with httpx.AsyncClient(timeout=60.0) as client:
                response = await client.post(
                    f"{self.llm_base_url}/api/generate",
                    json={
                        "model": self.LLM_CONFIG["model"],
                        "prompt": prompt,
                        "stream": False,
                        "options": {
                            "temperature": 0.5,
                            "num_ctx": 2048,
                        }
                    }
                )
                response.raise_for_status()
                result = response.json()
                return result.get("response", "").strip()

        except Exception as e:
            logger.error(f"Reformulation failed: {e}")
            return original_description

    async def generate_new_examples(
        self,
        pattern: str,
        language: str = "ja",
        count: int = 3
    ) -> List[RuleExample]:
        """
        Generate new example sentences for a grammar pattern.

        The examples are ORIGINAL, not from any source.
        """
        httpx = self._ensure_httpx()

        prompt = f"""Generate {count} example sentences using this grammar pattern.
Create ORIGINAL sentences, not copied from anywhere.

Pattern: {pattern}
Language: {language}

Return JSON array:
[
  {{"original": "Example in {language}", "translation": "English translation", "note": "Usage note"}}
]

Return ONLY the JSON array:"""

        try:
            async with httpx.AsyncClient(timeout=60.0) as client:
                response = await client.post(
                    f"{self.llm_base_url}/api/generate",
                    json={
                        "model": self.LLM_CONFIG["model"],
                        "prompt": prompt,
                        "stream": False,
                        "options": {
                            "temperature": 0.7,  # Higher for creativity
                            "num_ctx": 2048,
                        }
                    }
                )
                response.raise_for_status()
                result = response.json()
                output = result.get("response", "")

                # Parse JSON
                json_match = re.search(r'\[[\s\S]*\]', output)
                if json_match:
                    data = json.loads(json_match.group())
                    return [
                        RuleExample(
                            original=ex.get("original", ""),
                            translation=ex.get("translation", ""),
                            note=ex.get("note", "")
                        )
                        for ex in data
                    ]

        except Exception as e:
            logger.error(f"Example generation failed: {e}")

        return []


def verify_no_source_traces(grammar_json: Dict[str, Any]) -> bool:
    """
    Utility function to verify that a grammar JSON has no source traces.

    Args:
        grammar_json: The grammar dictionary to check

    Returns:
        True if clean, raises AssertionError if not

    Example:
        >>> verify_no_source_traces({"rules": [...]})
        True
    """
    json_str = json.dumps(grammar_json).lower()

    for word in FORBIDDEN_WORDS:
        assert word not in json_str, f"Found '{word}' in JSON!"

    return True

"""
================================================================================
AI_MODULE: Grammar Merger Service
AI_VERSION: 1.0.0
AI_DESCRIPTION: Merge di regole grammaticali con deduplicazione fuzzy
AI_BUSINESS: Unificazione regole da fonti multiple senza tracce fonte
AI_TEACHING: Fuzzy matching, deduplicazione, versioning, SQLite FTS
AI_DEPENDENCIES: sqlite3
AI_CREATED: 2026-02-05

LEGAL PRINCIPLE:
We merge rules from multiple sources to create ANONYMOUS grammar databases.
Only the COUNT of sources is stored, NEVER which sources.

OUTPUT FORMAT:
{
  "language": "ja",
  "last_updated": "2026-02-05",
  "sources_count": 3,  // HOW MANY, not WHICH
  "total_rules": 150,
  "rules": [...]
}
================================================================================
"""

import logging
import json
import sqlite3
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass, field
from datetime import datetime
from difflib import SequenceMatcher
import hashlib

from .rule_normalizer import NormalizedRule, RuleCategory, DifficultyLevel

logger = logging.getLogger(__name__)


@dataclass
class GrammarDatabase:
    """
    A complete grammar database for a language.

    NOTE: sources_count is the ONLY source info stored.
    We NEVER store which sources or any identifying info.
    """
    language: str
    last_updated: str
    sources_count: int  # Only count, not which!
    total_rules: int
    rules: List[NormalizedRule] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "language": self.language,
            "last_updated": self.last_updated,
            "sources_count": self.sources_count,
            "total_rules": self.total_rules,
            "rules": [r.to_dict() for r in self.rules]
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False, indent=indent)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "GrammarDatabase":
        """Load from dictionary."""
        rules = []
        for rule_data in data.get("rules", []):
            try:
                from .rule_normalizer import RuleExample
                examples = [
                    RuleExample(
                        original=ex.get("original", ""),
                        translation=ex.get("translation", ""),
                        note=ex.get("note", ""),
                        reading=ex.get("reading", "")
                    )
                    for ex in rule_data.get("examples", [])
                ]

                rule = NormalizedRule(
                    id=rule_data.get("id", ""),
                    category=RuleCategory(rule_data.get("category", "other")),
                    name=rule_data.get("name", ""),
                    description=rule_data.get("description", ""),
                    pattern=rule_data.get("pattern", ""),
                    examples=examples,
                    exceptions=rule_data.get("exceptions", []),
                    difficulty=DifficultyLevel(
                        rule_data.get("difficulty", "intermediate")
                    ),
                    related_rules=rule_data.get("related_rules", []),
                    tags=rule_data.get("tags", []),
                    created_at=rule_data.get("created_at", "")
                )
                rules.append(rule)
            except Exception as e:
                logger.warning(f"Failed to load rule: {e}")
                continue

        return cls(
            language=data.get("language", ""),
            last_updated=data.get("last_updated", ""),
            sources_count=data.get("sources_count", 0),
            total_rules=data.get("total_rules", len(rules)),
            rules=rules
        )


class GrammarMergerService:
    """
    Service for merging grammar rules from multiple extraction sessions.

    Features:
    - Fuzzy duplicate detection
    - Rule merging with best description selection
    - Example aggregation
    - Sources count tracking (count only, not which!)
    """

    # Fuzzy matching thresholds
    NAME_SIMILARITY_THRESHOLD = 0.85
    PATTERN_SIMILARITY_THRESHOLD = 0.90

    def __init__(self, storage_path: Optional[Path] = None):
        """
        Initialize the merger service.

        Args:
            storage_path: Where to store grammar JSON files
        """
        if storage_path:
            self.storage_path = Path(storage_path)
        else:
            self.storage_path = Path(__file__).parent.parent.parent / "data" / "grammar"

        self.storage_path.mkdir(parents=True, exist_ok=True)

    def get_grammar_file_path(self, language: str) -> Path:
        """Get the path to a grammar JSON file."""
        return self.storage_path / f"grammar_{language}.json"

    async def load_grammar(self, language: str) -> Optional[GrammarDatabase]:
        """
        Load existing grammar database for a language.

        Args:
            language: Language code (ja, zh, ko)

        Returns:
            GrammarDatabase or None if not exists
        """
        file_path = self.get_grammar_file_path(language)

        if not file_path.exists():
            return None

        try:
            with open(file_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            return GrammarDatabase.from_dict(data)

        except Exception as e:
            logger.error(f"Failed to load grammar for {language}: {e}")
            return None

    async def save_grammar(self, grammar: GrammarDatabase) -> bool:
        """
        Save grammar database to file.

        Args:
            grammar: GrammarDatabase to save

        Returns:
            True if successful
        """
        file_path = self.get_grammar_file_path(grammar.language)

        try:
            # Update metadata
            grammar.last_updated = datetime.utcnow().strftime("%Y-%m-%d")
            grammar.total_rules = len(grammar.rules)

            with open(file_path, "w", encoding="utf-8") as f:
                f.write(grammar.to_json())

            logger.info(
                f"Saved grammar for {grammar.language}: "
                f"{grammar.total_rules} rules"
            )
            return True

        except Exception as e:
            logger.error(f"Failed to save grammar: {e}")
            return False

    async def merge_rules(
        self,
        language: str,
        new_rules: List[NormalizedRule]
    ) -> GrammarDatabase:
        """
        Merge new rules into existing grammar database.

        - Deduplicates by fuzzy matching
        - Merges similar rules (combines examples)
        - Increments sources_count
        - Updates timestamps

        Args:
            language: Target language
            new_rules: New rules to merge

        Returns:
            Updated GrammarDatabase
        """
        # Load existing or create new
        existing = await self.load_grammar(language)

        if existing is None:
            existing = GrammarDatabase(
                language=language,
                last_updated=datetime.utcnow().strftime("%Y-%m-%d"),
                sources_count=0,
                total_rules=0,
                rules=[]
            )

        # Increment sources count (we processed a new source)
        existing.sources_count += 1

        # Build index for fuzzy matching
        rule_index = self._build_rule_index(existing.rules)

        # Process new rules
        for new_rule in new_rules:
            match = self._find_matching_rule(new_rule, rule_index)

            if match:
                # Merge into existing rule
                self._merge_into_rule(match, new_rule)
            else:
                # Add as new rule
                existing.rules.append(new_rule)
                rule_index[new_rule.id] = new_rule

        # Update metadata
        existing.total_rules = len(existing.rules)
        existing.last_updated = datetime.utcnow().strftime("%Y-%m-%d")

        # Save
        await self.save_grammar(existing)

        return existing

    def _build_rule_index(
        self,
        rules: List[NormalizedRule]
    ) -> Dict[str, NormalizedRule]:
        """Build an index of rules by ID."""
        return {rule.id: rule for rule in rules}

    def _find_matching_rule(
        self,
        new_rule: NormalizedRule,
        index: Dict[str, NormalizedRule]
    ) -> Optional[NormalizedRule]:
        """
        Find a matching rule using fuzzy matching.

        Matches by:
        1. Exact ID match
        2. Similar name (>85% similarity)
        3. Similar pattern (>90% similarity)
        """
        # Exact ID match
        if new_rule.id in index:
            return index[new_rule.id]

        # Fuzzy match on name and pattern
        for existing_rule in index.values():
            name_sim = SequenceMatcher(
                None,
                new_rule.name.lower(),
                existing_rule.name.lower()
            ).ratio()

            pattern_sim = SequenceMatcher(
                None,
                new_rule.pattern,
                existing_rule.pattern
            ).ratio()

            # Match if both name and pattern are similar
            if (name_sim >= self.NAME_SIMILARITY_THRESHOLD and
                pattern_sim >= self.PATTERN_SIMILARITY_THRESHOLD):
                return existing_rule

            # Match if pattern is very similar
            if pattern_sim >= 0.95:
                return existing_rule

        return None

    def _merge_into_rule(
        self,
        existing: NormalizedRule,
        new: NormalizedRule
    ):
        """
        Merge a new rule into an existing one.

        - Keeps longer/better description
        - Adds unique examples
        - Merges tags and related rules
        - Updates difficulty if more specific
        """
        # Keep longer description (likely more detailed)
        if len(new.description) > len(existing.description):
            existing.description = new.description

        # Add unique examples (by original text)
        existing_examples = {ex.original for ex in existing.examples}
        for ex in new.examples:
            if ex.original not in existing_examples:
                existing.examples.append(ex)
                existing_examples.add(ex.original)

        # Merge exceptions
        existing_exceptions = set(existing.exceptions)
        for exc in new.exceptions:
            if exc not in existing_exceptions:
                existing.exceptions.append(exc)
                existing_exceptions.add(exc)

        # Merge tags
        existing_tags = set(existing.tags)
        for tag in new.tags:
            if tag not in existing_tags:
                existing.tags.append(tag)
                existing_tags.add(tag)

        # Merge related rules
        existing_related = set(existing.related_rules)
        for rel in new.related_rules:
            if rel not in existing_related:
                existing.related_rules.append(rel)
                existing_related.add(rel)

    async def get_rules_by_category(
        self,
        language: str,
        category: RuleCategory
    ) -> List[NormalizedRule]:
        """Get all rules of a specific category."""
        grammar = await self.load_grammar(language)
        if grammar is None:
            return []

        return [r for r in grammar.rules if r.category == category]

    async def get_rules_by_difficulty(
        self,
        language: str,
        difficulty: DifficultyLevel
    ) -> List[NormalizedRule]:
        """Get all rules of a specific difficulty."""
        grammar = await self.load_grammar(language)
        if grammar is None:
            return []

        return [r for r in grammar.rules if r.difficulty == difficulty]

    async def search_rules(
        self,
        language: str,
        query: str
    ) -> List[NormalizedRule]:
        """
        Search rules by name, description, or pattern.

        Uses simple substring matching.
        """
        grammar = await self.load_grammar(language)
        if grammar is None:
            return []

        query_lower = query.lower()
        results = []

        for rule in grammar.rules:
            if (query_lower in rule.name.lower() or
                query_lower in rule.description.lower() or
                query_lower in rule.pattern.lower()):
                results.append(rule)

        return results

    async def export_to_anki(
        self,
        language: str,
        output_path: Optional[Path] = None
    ) -> Path:
        """
        Export grammar rules to Anki-compatible format.

        Returns path to the exported file.
        """
        grammar = await self.load_grammar(language)
        if grammar is None:
            raise ValueError(f"No grammar found for {language}")

        if output_path is None:
            output_path = self.storage_path / f"anki_{language}.txt"

        lines = []
        for rule in grammar.rules:
            # Front: pattern + name
            front = f"{rule.pattern} ({rule.name})"

            # Back: description + examples
            back_parts = [rule.description]
            for ex in rule.examples[:3]:  # Max 3 examples
                back_parts.append(f"例: {ex.original}")
                back_parts.append(f"    {ex.translation}")

            back = "<br>".join(back_parts)

            # Anki format: front\tback\ttags
            tags = " ".join(rule.tags + [rule.category.value, rule.difficulty.value])
            lines.append(f"{front}\t{back}\t{tags}")

        with open(output_path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines))

        return output_path

    async def get_statistics(self, language: str) -> Dict[str, Any]:
        """Get statistics about the grammar database."""
        grammar = await self.load_grammar(language)
        if grammar is None:
            return {"error": "No grammar found"}

        # Category distribution
        category_counts = {}
        for rule in grammar.rules:
            cat = rule.category.value
            category_counts[cat] = category_counts.get(cat, 0) + 1

        # Difficulty distribution
        difficulty_counts = {}
        for rule in grammar.rules:
            diff = rule.difficulty.value
            difficulty_counts[diff] = difficulty_counts.get(diff, 0) + 1

        return {
            "language": grammar.language,
            "last_updated": grammar.last_updated,
            "sources_count": grammar.sources_count,
            "total_rules": grammar.total_rules,
            "total_examples": sum(len(r.examples) for r in grammar.rules),
            "category_distribution": category_counts,
            "difficulty_distribution": difficulty_counts,
            "avg_examples_per_rule": (
                sum(len(r.examples) for r in grammar.rules) / len(grammar.rules)
                if grammar.rules else 0
            )
        }

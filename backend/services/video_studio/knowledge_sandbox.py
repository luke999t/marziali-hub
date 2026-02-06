"""
Knowledge Sandbox - Test Import & Query Simulation
===================================================

Sandbox per testare import e simulare query RAG:
- Preview import (dry-run)
- Query simulator con retrieval
- Comparison before/after
- Example queries per categoria
- Accuracy testing

Author: AI Assistant
Date: 2025-11-06
"""

import sys
from pathlib import Path
import json
from typing import List, Dict, Any, Tuple
from datetime import datetime
from collections import defaultdict

# Import componenti
sys.path.insert(0, str(Path(__file__).parent))
from knowledge_base_manager import KnowledgeBaseManager
from ai_conversational_agent import KnowledgeRetriever, RetrievedKnowledge


class KnowledgeSandbox:
    """
    Sandbox per testing import e query simulation

    Features:
    - Preview import senza applicare
    - Query simulator con top-K results
    - Comparison before/after merge
    - Example queries categorizzate
    """

    def __init__(self):
        self.manager = KnowledgeBaseManager()
        self.retriever = None

        # Example queries per categoria
        self.example_queries = {
            'basic_techniques': [
                "Come si esegue un pugno corretto?",
                "Qual è la posizione base nel karate?",
                "Come si fa un calcio frontale?",
                "Spiegami la guardia nel wing chun"
            ],
            'specific_styles': [
                "Quali sono le forme del tai chi?",
                "Raccontami della storia del kung fu",
                "Differenza tra karate e taekwondo",
                "Tecniche avanzate di muay thai"
            ],
            'corrections': [
                "Come correggere la posizione delle spalle nel pugno?",
                "Errori comuni nella posizione del cavallo",
                "Come migliorare l'equilibrio nel calcio?",
                "Problemi tipici nella rotazione dell'anca"
            ],
            'history': [
                "Storia delle arti marziali cinesi",
                "Origini del judo",
                "Evoluzione del karate moderno",
                "Maestri famosi di kung fu"
            ],
            'training': [
                "Come allenarsi per migliorare la velocità?",
                "Programma allenamento per principianti",
                "Esercizi per aumentare la flessibilità",
                "Routine giornaliera per arti marziali"
            ]
        }

    def preview_import(self, json_path: Path) -> Dict[str, Any]:
        """
        Preview import senza applicarlo (dry-run)

        Args:
            json_path: Path al JSON da importare

        Returns:
            Dict con preview completo:
            - new_items: Quanti item nuovi
            - duplicates: Lista duplicati con action
            - total_size_increase: Aumento dimensione KB
            - conflicts: Conflitti da risolvere
        """
        print("=" * 70)
        print(f"PREVIEW IMPORT: {json_path.name}")
        print("=" * 70)

        # Get preview da manager
        preview = self.manager.preview_merge(json_path)

        # Summary
        print(f"\nNEW ITEMS:")
        print(f"  - Forms: {preview['new_forms']}")
        print(f"  - Sequences: {preview['new_sequences']}")
        print(f"  - Patterns: {preview['new_patterns']}")
        print(f"  - Q&A Pairs: {preview['new_qa_pairs']}")
        print(f"  - TOTAL NEW: {preview['new_forms'] + preview['new_sequences'] + preview['new_patterns'] + preview['new_qa_pairs']}")

        # Duplicates
        print(f"\nDUPLICATES: {len(preview['duplicates'])}")
        if preview['duplicates']:
            print(f"  (Will merge attributes from both sources)")
            for dup in preview['duplicates'][:5]:
                print(f"  - {dup['type']}: {dup.get('name', dup.get('question', 'N/A')[:40])}")
            if len(preview['duplicates']) > 5:
                print(f"  ... and {len(preview['duplicates']) - 5} more")

        # File size
        if json_path.exists():
            file_size_kb = json_path.stat().st_size / 1024
            print(f"\nFILE SIZE: {file_size_kb:.1f} KB")

        print("\n" + "=" * 70)
        print("[OK] Preview complete - NO CHANGES APPLIED")
        print("=" * 70)

        return preview

    def load_for_testing(self, json_path: Path) -> bool:
        """
        Carica JSON in manager e crea retriever per testing

        Args:
            json_path: Path al JSON da caricare

        Returns:
            True se successo
        """
        print(f"\n>> Loading for testing: {json_path.name}")

        try:
            # Load in manager
            stats = self.manager.load_json(json_path)
            print(f"[OK] Loaded: {stats}")

            # Export temporaneo per retriever
            temp_path = self.manager.export_merged(
                self.manager.output_dir / "temp_test_kb.json"
            )

            # Create retriever
            self.retriever = KnowledgeRetriever(str(temp_path))
            self.retriever.load_knowledge_base()

            print(f"[OK] Retriever ready with {len(self.retriever.forms_db) + len(self.retriever.sequences_db)} items")

            return True

        except Exception as e:
            print(f"[ERROR] Error loading: {e}")
            return False

    def simulate_query(self, query: str, top_k: int = 5, show_details: bool = True) -> List[RetrievedKnowledge]:
        """
        Simula query con retrieval

        Args:
            query: Query da testare
            top_k: Numero risultati
            show_details: Mostra dettagli retrieval

        Returns:
            Lista RetrievedKnowledge
        """
        if self.retriever is None:
            print("[ERROR] No retriever loaded. Call load_for_testing() first.")
            return []

        print("\n" + "=" * 70)
        print(f"[SEARCH] QUERY SIMULATION")
        print("=" * 70)

        print(f"\n? Query: \"{query}\"")
        print(f"[STATS] Top-K: {top_k}")

        # Retrieve
        results = self.retriever.retrieve(query, top_k=top_k)

        print(f"\n[OK] Found {len(results)} results")

        if show_details:
            print("\n" + "-" * 70)
            print("RESULTS:")
            print("-" * 70)

            for i, result in enumerate(results, 1):
                print(f"\n#{i} - Relevance: {result.relevance_score:.3f}")
                print(f"Type: {result.item_type}")
                print(f"Content: {result.content.get('name', result.content.get('question_it', 'N/A'))[:60]}")

                if 'style' in result.content:
                    print(f"Style: {result.content['style']}")

                if 'category' in result.content:
                    print(f"Category: {result.content['category']}")

                if 'techniques' in result.content:
                    print(f"Techniques: {', '.join(result.content['techniques'][:3])}")

        return results

    def test_example_queries(self, category: str = None, show_details: bool = False) -> Dict[str, Any]:
        """
        Testa tutte le example queries per una categoria

        Args:
            category: Categoria da testare (None = tutte)
            show_details: Mostra dettagli ogni query

        Returns:
            Dict con accuracy stats
        """
        if self.retriever is None:
            print("[ERROR] No retriever loaded. Call load_for_testing() first.")
            return {}

        categories_to_test = [category] if category else list(self.example_queries.keys())

        print("\n" + "=" * 70)
        print("[TEST] TESTING EXAMPLE QUERIES")
        print("=" * 70)

        results = {
            'total_queries': 0,
            'total_results': 0,
            'avg_results_per_query': 0.0,
            'categories': {}
        }

        for cat in categories_to_test:
            queries = self.example_queries.get(cat, [])

            print(f"\n[CAT] Category: {cat.upper()}")
            print("-" * 70)

            cat_stats = {
                'queries_tested': len(queries),
                'total_results': 0,
                'queries_with_results': 0
            }

            for i, query in enumerate(queries, 1):
                if show_details:
                    retrieved = self.simulate_query(query, top_k=3, show_details=True)
                else:
                    # Quick test senza dettagli
                    retrieved = self.retriever.retrieve(query, top_k=3)
                    print(f"  {i}. \"{query[:50]}...\" → {len(retrieved)} results")

                cat_stats['total_results'] += len(retrieved)
                if len(retrieved) > 0:
                    cat_stats['queries_with_results'] += 1

            cat_stats['avg_results'] = cat_stats['total_results'] / cat_stats['queries_tested'] if cat_stats['queries_tested'] > 0 else 0

            print(f"\n  [OK] Results: {cat_stats['queries_with_results']}/{cat_stats['queries_tested']} queries got results")
            print(f"  [STATS] Avg results per query: {cat_stats['avg_results']:.1f}")

            results['categories'][cat] = cat_stats
            results['total_queries'] += cat_stats['queries_tested']
            results['total_results'] += cat_stats['total_results']

        # Overall stats
        results['avg_results_per_query'] = results['total_results'] / results['total_queries'] if results['total_queries'] > 0 else 0

        print("\n" + "=" * 70)
        print("[STATS] OVERALL STATS")
        print("=" * 70)
        print(f"Total queries tested: {results['total_queries']}")
        print(f"Total results retrieved: {results['total_results']}")
        print(f"Avg results per query: {results['avg_results_per_query']:.1f}")

        # Calculate success rate
        queries_with_results = sum([cat['queries_with_results'] for cat in results['categories'].values()])
        success_rate = (queries_with_results / results['total_queries'] * 100) if results['total_queries'] > 0 else 0

        print(f"Success rate (queries with results): {success_rate:.1f}%")

        return results

    def compare_before_after(self, json_to_add: Path) -> Dict[str, Any]:
        """
        Compara knowledge base before/after import

        Args:
            json_to_add: JSON da aggiungere

        Returns:
            Dict con comparison stats
        """
        print("\n" + "=" * 70)
        print("[MERGE] COMPARISON: BEFORE vs AFTER IMPORT")
        print("=" * 70)

        # Stats BEFORE
        stats_before = self.manager.get_stats()

        print(f"\n[STATS] BEFORE:")
        print(f"  • Total forms: {stats_before['summary']['total_forms']}")
        print(f"  • Total sequences: {stats_before['summary']['total_sequences']}")
        print(f"  • Total patterns: {stats_before['summary']['total_patterns']}")
        print(f"  • Total Q&A: {stats_before['summary']['total_qa_pairs']}")
        print(f"  • Total items: {stats_before['summary']['total_items']}")
        print(f"  • Total styles: {stats_before['total_styles']}")
        print(f"  • Total sources: {stats_before['total_sources']}")

        # Load new JSON
        print(f"\n[LOADING] Loading: {json_to_add.name}...")
        load_stats = self.manager.load_json(json_to_add)

        # Stats AFTER
        stats_after = self.manager.get_stats()

        print(f"\n[STATS] AFTER:")
        print(f"  • Total forms: {stats_after['summary']['total_forms']}")
        print(f"  • Total sequences: {stats_after['summary']['total_sequences']}")
        print(f"  • Total patterns: {stats_after['summary']['total_patterns']}")
        print(f"  • Total Q&A: {stats_after['summary']['total_qa_pairs']}")
        print(f"  • Total items: {stats_after['summary']['total_items']}")
        print(f"  • Total styles: {stats_after['total_styles']}")
        print(f"  • Total sources: {stats_after['total_sources']}")

        # Calculate DELTA
        print(f"\n[DELTA] DELTA:")
        print(f"  • Forms: +{stats_after['summary']['total_forms'] - stats_before['summary']['total_forms']}")
        print(f"  • Sequences: +{stats_after['summary']['total_sequences'] - stats_before['summary']['total_sequences']}")
        print(f"  • Patterns: +{stats_after['summary']['total_patterns'] - stats_before['summary']['total_patterns']}")
        print(f"  • Q&A: +{stats_after['summary']['total_qa_pairs'] - stats_before['summary']['total_qa_pairs']}")
        print(f"  • Total items: +{stats_after['summary']['total_items'] - stats_before['summary']['total_items']}")
        print(f"  • Styles: +{stats_after['total_styles'] - stats_before['total_styles']}")
        print(f"  • Sources: +{stats_after['total_sources'] - stats_before['total_sources']}")

        print(f"\n[MERGE] Merge operations:")
        print(f"  • Duplicates removed: {load_stats.get('duplicates', 0)}")
        print(f"  • Conflicts resolved: {self.manager.stats['conflicts_resolved']}")

        return {
            'before': stats_before,
            'after': stats_after,
            'load_stats': load_stats
        }

    def benchmark_retrieval(self, num_queries: int = 20) -> Dict[str, Any]:
        """
        Benchmark retrieval performance

        Args:
            num_queries: Numero query da testare

        Returns:
            Dict con performance metrics
        """
        import time

        if self.retriever is None:
            print("[ERROR] No retriever loaded.")
            return {}

        print("\n" + "=" * 70)
        print(f"[PERF] RETRIEVAL BENCHMARK - {num_queries} queries")
        print("=" * 70)

        # Collect test queries
        all_queries = []
        for queries in self.example_queries.values():
            all_queries.extend(queries)

        test_queries = (all_queries * (num_queries // len(all_queries) + 1))[:num_queries]

        # Benchmark
        timings = []
        results_counts = []

        print("\nRunning benchmark...")

        for query in test_queries:
            start = time.perf_counter()
            results = self.retriever.retrieve(query, top_k=5)
            elapsed = time.perf_counter() - start

            timings.append(elapsed * 1000)  # ms
            results_counts.append(len(results))

        # Stats
        avg_time = sum(timings) / len(timings)
        min_time = min(timings)
        max_time = max(timings)
        avg_results = sum(results_counts) / len(results_counts)

        print(f"\n[STATS] RESULTS:")
        print(f"  • Queries tested: {num_queries}")
        print(f"  • Avg retrieval time: {avg_time:.2f} ms")
        print(f"  • Min time: {min_time:.2f} ms")
        print(f"  • Max time: {max_time:.2f} ms")
        print(f"  • Avg results per query: {avg_results:.1f}")

        # Performance rating
        if avg_time < 10:
            rating = "[PERF] EXCELLENT"
        elif avg_time < 50:
            rating = "[OK] GOOD"
        elif avg_time < 100:
            rating = "[WARN]  ACCEPTABLE"
        else:
            rating = "[ERROR] SLOW"

        print(f"\n{rating} (Target: <50ms)")

        return {
            'queries_tested': num_queries,
            'avg_time_ms': avg_time,
            'min_time_ms': min_time,
            'max_time_ms': max_time,
            'avg_results': avg_results
        }


def main():
    """Demo/Test Sandbox"""

    print("=" * 70)
    print("KNOWLEDGE SANDBOX - Demo")
    print("=" * 70)

    sandbox = KnowledgeSandbox()

    # Path al JSON esistente
    qa_json = Path(r"C:\Users\utente\Desktop\knowledge_base_martial_arts\qa_dataset.json")

    if not qa_json.exists():
        print(f"[ERROR] File not found: {qa_json}")
        return

    # 1. PREVIEW IMPORT
    print("\n" + "=" * 70)
    print("1. PREVIEW IMPORT (DRY-RUN)")
    print("=" * 70)

    preview = sandbox.preview_import(qa_json)
    input("\nPress ENTER to continue...")

    # 2. LOAD FOR TESTING
    print("\n" + "=" * 70)
    print("2. LOAD FOR TESTING")
    print("=" * 70)

    sandbox.load_for_testing(qa_json)
    input("\nPress ENTER to continue...")

    # 3. SIMULATE SINGLE QUERY
    print("\n" + "=" * 70)
    print("3. SIMULATE QUERY")
    print("=" * 70)

    sandbox.simulate_query("Come si esegue un pugno corretto nel karate?", top_k=3, show_details=True)
    input("\nPress ENTER to continue...")

    # 4. TEST EXAMPLE QUERIES
    print("\n" + "=" * 70)
    print("4. TEST EXAMPLE QUERIES")
    print("=" * 70)

    sandbox.test_example_queries(show_details=False)
    input("\nPress ENTER to continue...")

    # 5. BENCHMARK RETRIEVAL
    print("\n" + "=" * 70)
    print("5. BENCHMARK RETRIEVAL")
    print("=" * 70)

    sandbox.benchmark_retrieval(num_queries=20)

    print("\n" + "=" * 70)
    print("[OK] SANDBOX DEMO COMPLETE")
    print("=" * 70)


if __name__ == "__main__":
    main()

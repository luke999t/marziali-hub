"""
Test AI Conversational Agent Integration Fix
============================================

Tests that ConversationalAgent now automatically loads knowledge base
and retrieves items correctly when integrated.
"""

import sys
import os
from pathlib import Path
import time

# Force UTF-8 encoding for Windows console
if os.name == 'nt':
    import codecs
    sys.stdout = codecs.getwriter('utf-8')(sys.stdout.buffer, 'strict')
    sys.stderr = codecs.getwriter('utf-8')(sys.stderr.buffer, 'strict')

# Add src to path
sys.path.insert(0, str(Path(__file__).parent))

from ai_conversational_agent import ConversationalAgent, KnowledgeRetriever

def test_agent_integration():
    """Test ConversationalAgent with knowledge base integration"""

    print("=" * 80)
    print("TESTING AI CONVERSATIONAL AGENT INTEGRATION FIX")
    print("=" * 80)

    # Path to merged knowledge base
    kb_path = Path(r'C:\Users\utente\Desktop\knowledge_base_martial_arts\merged_knowledge_FINAL_v2.json')

    if not kb_path.exists():
        print(f"\n❌ ERROR: Knowledge base not found at {kb_path}")
        return False

    print(f"\n✅ Knowledge base found: {kb_path}")

    # Test 1: Create agent (should auto-load knowledge base)
    print("\n" + "=" * 80)
    print("TEST 1: ConversationalAgent Initialization")
    print("=" * 80)

    start_time = time.time()
    agent = ConversationalAgent(
        knowledge_base_path=kb_path,
        llm_provider="openai",  # Will use fallback if no API key
        llm_model="gpt-4"
    )
    elapsed = time.time() - start_time

    print(f"✅ Agent initialized in {elapsed*1000:.2f}ms")

    # Check if knowledge base was loaded
    forms_count = len(agent.retriever.forms_db)
    sequences_count = len(agent.retriever.sequences_db)
    keywords_count = len(agent.retriever.keyword_index)

    print(f"\nKnowledge Base Status:")
    print(f"  - Forms: {forms_count}")
    print(f"  - Sequences: {sequences_count}")
    print(f"  - Keywords indexed: {keywords_count}")

    if forms_count == 0 and sequences_count == 0:
        print("\n❌ ERROR: Knowledge base NOT loaded automatically!")
        return False

    print("\n✅ Knowledge base loaded automatically!")

    # Test 2: Test retrieval integration
    print("\n" + "=" * 80)
    print("TEST 2: Knowledge Retrieval Integration")
    print("=" * 80)

    test_queries = [
        "bjj guardia",
        "krav maga difesa",
        "karate kata",
        "tai chi forma",
        "judo tecniche"
    ]

    results = []
    for query in test_queries:
        start_time = time.time()
        retrieved = agent.retriever.retrieve(query, top_k=3)
        elapsed = time.time() - start_time

        success = len(retrieved) > 0
        results.append({
            'query': query,
            'retrieved': len(retrieved),
            'success': success,
            'time_ms': elapsed * 1000
        })

        status = "✅" if success else "❌"
        print(f"{status} Query: '{query}' → {len(retrieved)} results ({elapsed*1000:.2f}ms)")

        if retrieved:
            for item in retrieved[:1]:  # Show first result
                print(f"    → {item.summary} (relevance: {item.relevance_score:.2f})")

    # Calculate success rate
    success_count = sum(1 for r in results if r['success'])
    total_count = len(results)
    success_rate = (success_count / total_count) * 100
    avg_time = sum(r['time_ms'] for r in results) / total_count

    print(f"\nRetrieval Statistics:")
    print(f"  - Success rate: {success_rate:.1f}% ({success_count}/{total_count})")
    print(f"  - Average time: {avg_time:.2f}ms")

    if success_rate < 60:
        print("\n⚠️ WARNING: Low success rate!")
    else:
        print("\n✅ Integration working correctly!")

    # Test 3: Test conversational agent (with fallback response)
    print("\n" + "=" * 80)
    print("TEST 3: Full Conversation Flow")
    print("=" * 80)

    # Start conversation
    conv_id = agent.start_conversation(user_level="beginner")
    print(f"✅ Conversation started: {conv_id}")

    # Ask question
    test_question = "Come si fa una guardia chiusa nel BJJ?"
    print(f"\nUser: {test_question}")

    start_time = time.time()
    response, metadata = agent.ask(test_question)
    elapsed = time.time() - start_time

    print(f"AI: {response[:200]}...")
    print(f"\nResponse time: {elapsed*1000:.2f}ms")

    # Check if knowledge was retrieved
    retrieved_items = metadata.get('retrieved_knowledge', [])
    print(f"\nRetrieved knowledge: {len(retrieved_items)} items")
    for item in retrieved_items:
        print(f"  - {item}")

    if len(retrieved_items) > 0:
        print("\n✅ Knowledge retrieval working in full conversation flow!")
    else:
        print("\n⚠️ No knowledge retrieved (query might not match)")

    # Final summary
    print("\n" + "=" * 80)
    print("INTEGRATION TEST SUMMARY")
    print("=" * 80)

    if forms_count > 0 and success_rate >= 60:
        print("\n✅ ALL TESTS PASSED!")
        print("\nFix Status:")
        print("  ✅ Knowledge base auto-loads on agent initialization")
        print("  ✅ Retrieval integration working correctly")
        print(f"  ✅ {success_rate:.0f}% success rate on test queries")
        print(f"  ✅ Average retrieval time: {avg_time:.2f}ms")
        return True
    else:
        print("\n❌ SOME TESTS FAILED")
        return False


if __name__ == '__main__':
    try:
        success = test_agent_integration()
        sys.exit(0 if success else 1)
    except Exception as e:
        print(f"\n❌ ERROR: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

"""
================================================================================
AI_MODULE: Grammar Extractor Test Fixtures
AI_VERSION: 1.0.0
AI_DESCRIPTION: Fixture per test di estrazione grammatica
AI_BUSINESS: Dati di test per validazione pipeline
AI_TEACHING: pytest fixtures, test data generation
AI_CREATED: 2026-02-05

ZERO MOCK POLICY:
- These are real test data, not mocks
- Used to test real extraction pipeline
================================================================================
"""

import pytest
from pathlib import Path


# Sample grammar texts for different languages
SAMPLE_JAPANESE_GRAMMAR = """
日本語文法の基礎

第1章: 助詞

1.1 助詞「は」(wa) - トピックマーカー
「は」は文の主題を示す助詞です。主語とは異なり、話題の中心を示します。

パターン: [名詞]は[述語]

例文:
- 私は学生です。(Watashi wa gakusei desu.) - 私が学生であることを表す
- 東京は日本の首都です。(Tokyo wa nihon no shuto desu.)
- 今日は暑いです。(Kyou wa atsui desu.)

注意点:
- 存在動詞（いる、ある）とは通常使わない
- 対比を表す時にも使用

1.2 助詞「が」(ga) - 主語マーカー
「が」は主語を明確に示す助詞です。新情報や強調に使います。

パターン: [名詞]が[動詞/形容詞]

例文:
- 誰が来ましたか。(Dare ga kimashita ka?) - 疑問詞と共に
- 鳥が飛んでいます。(Tori ga tonde imasu.) - 存在/動作の主体

第2章: 動詞の活用

2.1 て形 (te-form)
動詞を接続する際に使う形です。

パターン: [動詞-て形] + [続く動詞/補助動詞]

例文:
- 食べて寝る。(Tabete neru.) - 連続する動作
- 見て聞いて学ぶ。(Mite kiite manabu.)

2.2 ている形 (te-iru form)
進行中の動作や状態を表します。

パターン: [動詞-て形]いる

例文:
- 本を読んでいます。(Hon wo yonde imasu.) - 進行中
- 東京に住んでいます。(Tokyo ni sunde imasu.) - 状態
"""

SAMPLE_CHINESE_GRAMMAR = """
中文语法基础

第一章：基本句型

1.1 是...的 结构
用于强调时间、地点、方式等。

句型：[主语]是[时间/地点/方式]的

例句：
- 我是昨天来的。(Wǒ shì zuótiān lái de.) - 强调时间
- 他是在北京学的中文。(Tā shì zài Běijīng xué de zhōngwén.) - 强调地点

1.2 把字句
用于表示对事物的处置。

句型：[主语]把[宾语][动词短语]

例句：
- 请把门关上。(Qǐng bǎ mén guān shàng.) - 处置
- 我把作业做完了。(Wǒ bǎ zuòyè zuò wán le.) - 完成

第二章：补语

2.1 结果补语
表示动作的结果。

句型：[动词][结果补语]

例句：
- 看见 (kàn jiàn) - 看到
- 听懂 (tīng dǒng) - 听明白
"""

SAMPLE_KOREAN_GRAMMAR = """
한국어 문법 기초

제1장: 조사

1.1 주격조사 이/가
주어를 나타내는 조사입니다.

패턴: [명사]이/가 (받침 있으면 '이', 없으면 '가')

예문:
- 학생이 공부해요. (Haksaeng-i gongbuhaeyo.) - 학생이 주어
- 사과가 맛있어요. (Sagwa-ga masisseoyo.) - 사과가 주어

1.2 목적격조사 을/를
목적어를 나타내는 조사입니다.

패턴: [명사]을/를 (받침 있으면 '을', 없으면 '를')

예문:
- 밥을 먹어요. (Bab-eul meogeoyo.) - 밥이 목적어
- 커피를 마셔요. (Keopi-reul masyeoyo.) - 커피가 목적어
"""


@pytest.fixture
def japanese_grammar_text():
    """Sample Japanese grammar text."""
    return SAMPLE_JAPANESE_GRAMMAR


@pytest.fixture
def chinese_grammar_text():
    """Sample Chinese grammar text."""
    return SAMPLE_CHINESE_GRAMMAR


@pytest.fixture
def korean_grammar_text():
    """Sample Korean grammar text."""
    return SAMPLE_KOREAN_GRAMMAR


@pytest.fixture
def all_grammar_samples():
    """All grammar samples by language."""
    return {
        "ja": SAMPLE_JAPANESE_GRAMMAR,
        "zh": SAMPLE_CHINESE_GRAMMAR,
        "ko": SAMPLE_KOREAN_GRAMMAR,
    }


@pytest.fixture
def expected_japanese_rules():
    """Expected rules from Japanese sample."""
    return [
        {
            "name_contains": "は",
            "category": "particle",
            "min_examples": 2,
        },
        {
            "name_contains": "が",
            "category": "particle",
            "min_examples": 2,
        },
        {
            "name_contains": "て形",
            "category": "verb_form",
            "min_examples": 1,
        },
    ]


@pytest.fixture
def forbidden_source_words():
    """Words that must NEVER appear in output."""
    return [
        "source",
        "book",
        "author",
        "page",
        "isbn",
        "publisher",
        "chapter",
        "edition",
        "copyright",
        "rights",
        "reserved",
        "textbook",
        "manual",
        "guide",
        "volume",
        "citation",
    ]


# Sample extracted rules for testing merger
@pytest.fixture
def sample_normalized_rules():
    """Sample normalized rules for testing."""
    from services.language_learning.rule_normalizer import (
        NormalizedRule,
        RuleCategory,
        DifficultyLevel,
        RuleExample,
    )

    return [
        NormalizedRule(
            id="rule_ja_particle_wa",
            category=RuleCategory.PARTICLE,
            name="Particella は (wa)",
            description="Marca il topic della frase, distinguendolo dal soggetto grammaticale. Indica di cosa si sta parlando.",
            pattern="[NOUN]は[PREDICATE]",
            examples=[
                RuleExample(
                    original="私は学生です",
                    translation="Io sono studente",
                    note="Topic marking base",
                ),
                RuleExample(
                    original="今日は暑いです",
                    translation="Oggi fa caldo",
                    note="Topic temporale",
                ),
            ],
            exceptions=["Non usare con verbi di esistenza いる/ある"],
            difficulty=DifficultyLevel.BASIC,
            related_rules=["particella_ga", "particella_wo"],
            tags=["particle", "topic", "basic"],
        ),
        NormalizedRule(
            id="rule_ja_particle_ga",
            category=RuleCategory.PARTICLE,
            name="Particella が (ga)",
            description="Marca il soggetto grammaticale della frase. Usata per nuove informazioni o enfasi.",
            pattern="[NOUN]が[VERB/ADJ]",
            examples=[
                RuleExample(
                    original="誰が来ましたか",
                    translation="Chi è venuto?",
                    note="Con interrogativi",
                ),
            ],
            exceptions=["Dopo parole interrogative si usa sempre が"],
            difficulty=DifficultyLevel.BASIC,
            related_rules=["particella_wa"],
            tags=["particle", "subject", "basic"],
        ),
        NormalizedRule(
            id="rule_ja_te_form",
            category=RuleCategory.VERB_FORM,
            name="Forma て (te-form)",
            description="Forma verbale usata per connettere azioni in sequenza, fare richieste, e costruire forme progressive.",
            pattern="[VERB-て][CONTINUATION]",
            examples=[
                RuleExample(
                    original="食べて寝る",
                    translation="Mangiare e dormire",
                    note="Sequenza azioni",
                ),
            ],
            exceptions=[],
            difficulty=DifficultyLevel.ELEMENTARY,
            related_rules=["te_iru_form"],
            tags=["verb", "conjugation", "connection"],
        ),
    ]


@pytest.fixture
def grammar_storage_path(tmp_path):
    """Temporary storage path for grammar files."""
    storage = tmp_path / "grammar"
    storage.mkdir(parents=True, exist_ok=True)
    return storage

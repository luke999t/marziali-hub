# US-002: Grammar Extractor - Asian Languages

## Overview
Extract grammar rules from Chinese/Japanese/Korean text for martial arts learning.

## Technical Requirements

### 1. Grammar Extractor (`backend/services/language_learning/grammar_extractor.py`)

```python
"""
🎓 AI_MODULE: GrammarExtractor
🎓 AI_DESCRIPTION: Extracts grammar patterns from CJK text
🎓 AI_BUSINESS: Enables martial arts terminology learning
🎓 AI_TEACHING: NLP tokenization with language-specific libraries
"""

class GrammarExtractor:
    def __init__(self)
    def extract_chinese(self, text: str) -> GrammarResult
    def extract_japanese(self, text: str) -> GrammarResult
    def extract_korean(self, text: str) -> GrammarResult
    def detect_language(self, text: str) -> str
```

### 2. Chinese Extraction

**Library:** jieba (segmentation) + pypinyin (pronunciation)

**Extract:**
- Word segmentation
- Pinyin pronunciation
- Character components (radicals)
- Common patterns (measure words, particles)

**Tasks:**
- [ ] Install jieba, pypinyin
- [ ] Implement extract_chinese()
- [ ] Return word list with pinyin
- [ ] Identify grammar particles (的, 了, 在, etc.)

### 3. Japanese Extraction

**Library:** fugashi (MeCab wrapper)

**Extract:**
- Morphological analysis
- Verb conjugations (dictionary form, te-form, etc.)
- Particles (は, が, を, に, etc.)
- Kanji readings

**Tasks:**
- [ ] Install fugashi, unidic-lite
- [ ] Implement extract_japanese()
- [ ] Return word list with readings
- [ ] Identify verb forms and conjugations

### 4. Korean Extraction

**Library:** konlpy (Okt tokenizer)

**Extract:**
- Morpheme analysis
- Verb conjugations
- Particles (은/는, 이/가, 을/를)
- Honorific levels

**Tasks:**
- [ ] Install konlpy
- [ ] Implement extract_korean()
- [ ] Return morpheme list
- [ ] Identify grammar particles

### 5. API Endpoint (`backend/api/v1/endpoints/grammar_learning.py`)

```python
@router.post("/grammar/extract")
async def extract_grammar(request: GrammarRequest) -> GrammarResponse:
    """
    POST /api/v1/grammar/extract
    Body: {"text": "太极拳是中国武术", "language": "zh"}
    Response: {
        "words": [
            {"word": "太极拳", "pinyin": "tài jí quán", "type": "noun"},
            {"word": "是", "pinyin": "shì", "type": "verb"},
            ...
        ],
        "particles": ["是"],
        "patterns": ["N + 是 + N"]
    }
    """
```

**Tasks:**
- [ ] Create router with POST endpoint
- [ ] Auto-detect language if not specified
- [ ] Return structured grammar data
- [ ] Add to main.py router includes

### 6. Unit Tests (`backend/tests/unit/test_grammar_extractor.py`)

```python
"""
⚠️ ZERO MOCK TEST - Tests real extraction
No network required, but real libraries must work
"""

def test_chinese_extraction():
    extractor = GrammarExtractor()
    result = extractor.extract_chinese("太极拳是中国武术")
    assert len(result.words) > 0
    assert "太极拳" in [w.word for w in result.words]

def test_japanese_extraction():
    extractor = GrammarExtractor()
    result = extractor.extract_japanese("空手は日本の武道です")
    assert len(result.words) > 0
```

**Tasks:**
- [ ] Test Chinese extraction
- [ ] Test Japanese extraction
- [ ] Test Korean extraction
- [ ] Test language detection
- [ ] Test edge cases (empty, mixed language)

## Dependencies

```txt
# Chinese
jieba>=0.42.1
pypinyin>=0.48.0

# Japanese
fugashi>=1.3.0
unidic-lite>=1.0.8

# Korean
konlpy>=0.6.0
```

## Sample Data

### Chinese Martial Arts Terms
```
太极拳 - Tai Chi
少林功夫 - Shaolin Kung Fu
咏春拳 - Wing Chun
八卦掌 - Baguazhang
```

### Japanese Martial Arts Terms
```
空手 - Karate
柔道 - Judo
剣道 - Kendo
合気道 - Aikido
```

### Korean Martial Arts Terms
```
태권도 - Taekwondo
합기도 - Hapkido
씨름 - Ssireum
```

## Acceptance Criteria Checklist

- [ ] Extracts particles and verb conjugations
- [ ] Supports Chinese (simplified/traditional)
- [ ] Supports Japanese
- [ ] Supports Korean
- [ ] Stores rules in backend/data/grammar/
- [ ] API endpoint POST /api/v1/grammar/extract works
- [ ] ZERO MOCK test with real text samples

## Estimated Effort

- Chinese extraction: 2 hours
- Japanese extraction: 3 hours (MeCab setup)
- Korean extraction: 2 hours
- API Endpoint: 1 hour
- Tests: 2 hours
- **Total: 10 hours**

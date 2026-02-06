# Fix Plan - Marziali Hub

## 🎯 Current Sprint Tasks

### Priority HIGH

- [ ] **US-001: Translation Debate Ollama** 
  - Verify Ollama is running: `ollama list`
  - Test ollama_engine.py connects to qwen2.5:7b
  - Test translation_debate.py uses both models
  - Create integration test (ZERO MOCK)
  - Files: `backend/services/translation/`

- [ ] **US-002: Grammar Extractor**
  - Check dependencies: jieba, fugashi, konlpy
  - Test extraction on sample Chinese text
  - Test extraction on sample Japanese text
  - Create unit test (ZERO MOCK)
  - Files: `backend/services/language_learning/`

### Priority MEDIUM

- [ ] **US-003: Backend Health**
  - Run: `cd backend && uvicorn main:app --port 8000`
  - Fix any import errors
  - Verify /health returns 200
  - Verify /docs loads Swagger

- [ ] **US-004: Frontend Auth**
  - Check AuthContext.tsx for token handling
  - Fix redirect after login
  - Test logout clears state

### Priority LOW

- [ ] **US-005: Skeleton Extraction** - Requires MediaPipe setup
- [ ] **US-006: AI-First Headers** - Ongoing documentation task

---

## ✅ Completed Tasks

(Tasks move here when `passes: true` in prd.json)

---

## 📝 Notes & Learnings

- Ollama models available: qwen2.5:7b, llama3.1:8b
- mistral:7b NOT available (disk space issue)
- Backend port: 8000
- Frontend port: 3000
- ZERO MOCK rule: Tests MUST fail if backend is off

---

## 🔧 Quick Commands

```bash
# Start Ollama
ollama serve

# Check models
ollama list

# Start backend
cd backend && uvicorn main:app --reload --port 8000

# Run tests (backend must be running!)
cd backend && pytest -v

# Start frontend
cd frontend && npm run dev
```

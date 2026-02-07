# Fix Plan - Marziali Hub

> **Last Updated:** 2026-02-06
> **Current Focus:** US-001 Translation Debate System
> **Active Task:** Task 1.1.1

---

## 📋 How To Use This File

1. Find the first `[ ]` unchecked task
2. Read the spec file for details: `.ralph/specs/US-XXX-*.md`
3. Complete the task
4. Mark it `[x]` with date: `[x] Task ... ✅ 2026-02-06`
5. Update DEVELOPMENT_STATUS.md
6. Commit

---

## 🎯 US-001: Translation Debate System (HIGH)

**Spec:** `.ralph/specs/US-001-translation-debate.md` + `US-001-part2-modules.md`
**Status:** 🟡 IN PROGRESS (0/28 tasks)

### Module 1: OllamaEngine (12 tasks)

- [ ] Task 1.1.1: Create file with AI-First header
- [ ] Task 1.1.2: Define data classes (TranslationResult, OllamaError)
- [ ] Task 1.1.3: Add imports and constants
- [ ] Task 1.1.4: Create OllamaEngine class skeleton
- [ ] Task 1.1.5: Add async context manager
- [ ] Task 1.1.6: Implement is_available() health check
- [ ] Task 1.1.7: Implement _make_request() with retry
- [ ] Task 1.1.8: Implement translate() method
- [ ] Task 1.1.9: Create unit test file with header
- [ ] Task 1.1.10: Add prerequisite check tests
- [ ] Task 1.1.11: Add OllamaEngine unit tests
- [ ] Task 1.1.12: Add enterprise test suite

### Module 2: TranslationDebate (8 tasks)

- [ ] Task 1.2.1: Create file with AI-First header
- [ ] Task 1.2.2: Define DebateResult and DebateRound dataclasses
- [ ] Task 1.2.3: Create TranslationDebate class skeleton
- [ ] Task 1.2.4: Implement _calculate_agreement() helper
- [ ] Task 1.2.5: Implement _check_models_available()
- [ ] Task 1.2.6: Implement _single_model_fallback()
- [ ] Task 1.2.7: Implement _run_debate_round()
- [ ] Task 1.2.8: Implement debate() main method

### Module 3: API Endpoint (4 tasks)

- [ ] Task 1.3.1: Create API router file with header
- [ ] Task 1.3.2: Define Pydantic request/response models
- [ ] Task 1.3.3: Implement POST /translation/debate endpoint
- [ ] Task 1.3.4: Register router in main.py

### Module 4: Integration Tests (4 tasks)

- [ ] Task 1.4.1: Create integration test file
- [ ] Task 1.4.2: Add happy path integration tests
- [ ] Task 1.4.3: Add error handling integration tests
- [ ] Task 1.4.4: Add performance integration tests

### Quality Gate (after all tasks)

- [ ] All tests pass: `pytest backend/tests -v`
- [ ] Coverage ≥ 90%: `pytest --cov`
- [ ] No mock imports in tests
- [ ] All files have AI-First headers
- [ ] Update prd.json: `"passes": true` for US-001

---

## 🎯 US-002: Grammar Extractor (HIGH)

**Spec:** `.ralph/specs/US-002-grammar-extractor.md`
**Status:** 🔴 TODO (0/? tasks)

_(Tasks will be detailed when US-001 is complete)_

---

## 🎯 US-003: Backend Health (MEDIUM)

**Spec:** `.ralph/specs/US-003-backend-health.md`
**Status:** 🔴 TODO

---

## 🎯 US-004: Frontend Auth (MEDIUM)

**Spec:** `.ralph/specs/US-004-frontend-auth.md`
**Status:** 🔴 TODO

---

## ✅ Completed Tasks

_(Move completed user stories here)_

---

## 📝 Session Notes

### 2026-02-06
- Ralph setup completed
- GitHub repo: https://github.com/luke999t/marziali-hub
- Created 28 granular tasks for US-001
- Ollama models ready: qwen2.5:7b ✅, llama3.1:8b ✅

---

## 🔧 Quick Commands

```bash
# Check prerequisites
ollama list
curl http://localhost:8000/health

# Start services
ollama serve
cd backend && uvicorn main:app --reload --port 8000

# Run tests
cd backend && pytest -v
cd backend && pytest --cov=backend/services

# Git
git add . && git commit -m "feat: description" && git push
```

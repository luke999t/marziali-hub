# Marziali Hub - AI-First Martial Arts Media Center

## 🎯 Product Vision

Platform for martial arts practitioners combining:
- **Video Analysis**: MediaPipe skeleton extraction for technique comparison
- **Multi-Language Translation**: Debate-based translation using local LLMs (Ollama)
- **Grammar Learning**: Extract language patterns from Chinese/Japanese/Korean texts
- **Content Library**: Streaming video with pose overlay

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     FRONTEND (Next.js 14)                   │
│  ┌─────────┐  ┌─────────┐  ┌─────────┐  ┌─────────┐        │
│  │Dashboard│  │ Video   │  │Grammar  │  │ Auth    │        │
│  │         │  │ Player  │  │Learning │  │ Pages   │        │
│  └────┬────┘  └────┬────┘  └────┬────┘  └────┬────┘        │
└───────┼────────────┼────────────┼────────────┼──────────────┘
        │            │            │            │
        ▼            ▼            ▼            ▼
┌─────────────────────────────────────────────────────────────┐
│                   BACKEND (FastAPI)                          │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐       │
│  │ Translation  │  │   Grammar    │  │   Video      │       │
│  │ Debate       │  │   Extractor  │  │   Studio     │       │
│  │ (Ollama)     │  │              │  │   (MediaPipe)│       │
│  └──────────────┘  └──────────────┘  └──────────────┘       │
└─────────────────────────────────────────────────────────────┘
        │                    │                    │
        ▼                    ▼                    ▼
┌─────────────┐      ┌─────────────┐      ┌─────────────┐
│   Ollama    │      │ PostgreSQL  │      │   Storage   │
│ qwen2.5:7b  │      │ + pgvector  │      │   (files)   │
│ llama3.1:8b │      │             │      │             │
└─────────────┘      └─────────────┘      └─────────────┘
```

## 📁 Project Structure

```
marziali-hub/
├── backend/                    # FastAPI Python
│   ├── main.py                # Entry point (port 8000)
│   ├── api/v1/                # REST endpoints
│   ├── services/
│   │   ├── translation/       # Debate system
│   │   ├── language_learning/ # Grammar extractor
│   │   └── video_studio/      # MediaPipe processing
│   ├── tests/                 # ZERO MOCK tests
│   └── data/                  # JSON data files
├── frontend/                  # Next.js 14
│   ├── src/app/              # App router pages
│   ├── src/components/       # React components
│   └── src/contexts/         # Auth, Theme contexts
├── flutter_app/              # Mobile app
└── .ralph/                   # Ralph configuration
```

## 🚨 CRITICAL DEVELOPMENT RULES

### RULE 1: ZERO MOCK - LEGGE SUPREMA
```
❌ VIETATO: jest.mock(), MagicMock, AsyncMock, @patch
❌ VIETATO: Tests that pass with backend off
✅ REQUIRED: Tests call REAL APIs on localhost:8000
✅ REQUIRED: Tests FAIL if backend not running
```

### RULE 2: AI-FIRST HEADERS
Every Python file must have:
```python
"""
🎓 AI_MODULE: [Name]
🎓 AI_DESCRIPTION: [One line]
🎓 AI_BUSINESS: [Business value]
🎓 AI_TEACHING: [Technical concept]

🔄 ALTERNATIVE_VALUTATE:
- [Option]: Rejected because [reason]

💡 PERCHÉ_QUESTA_SOLUZIONE:
- [Advantage]
"""
```

### RULE 3: LEGO MODULAR
- Functions reusable across verticals
- Core modules: 100% reuse
- Business modules: 70-85% reuse

### RULE 4: DIDACTIC COMMENTS
```python
# ❌ WRONG: Calculate discount
# ✅ RIGHT: Progressive discount based on loyalty (5%/year, max 15%)
```

## 🔧 Quick Start

```bash
# Backend
cd backend
pip install -r requirements.txt
uvicorn main:app --reload --port 8000

# Frontend
cd frontend
npm install --legacy-peer-deps
npm run dev

# Ollama (required for translation)
ollama serve
ollama list  # Should show qwen2.5:7b, llama3.1:8b
```

## 📋 Current Sprint

See `.ralph/fix_plan.md` for active tasks.
See `.ralph/prd.json` for user stories.
See `.ralph/DEVELOPMENT_STATUS.md` for progress tracking.

## 🔗 Resources

- GitHub: https://github.com/luke999t/marziali-hub
- Backend API: http://localhost:8000/docs
- Frontend: http://localhost:3000

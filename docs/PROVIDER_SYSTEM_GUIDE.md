# 🔌 Pluggable Provider System - Complete Guide

## Overview

Il sistema di traduzione live supporta **provider multipli** switchabili via configurazione:

### Provider Disponibili:

| Service | Provider | Type | Cost | Latency | Accuracy |
|---------|----------|------|------|---------|----------|
| **Speech** | Whisper (default) | Open source | €0 | ~200-300ms | ~95% |
| **Speech** | Google Cloud | Cloud API | ~€1.44/ora | ~100-300ms | ~95-98% |
| **Translation** | NLLB (default) | Open source | €0 | ~50-150ms | ~90-95% |
| **Translation** | Google Cloud | Cloud API | ~€20/1M char | ~50-150ms | ~98% |

---

## 🏗️ Architettura

### Pattern Strategy + Factory

```python
# Protocol (interfaccia)
class SpeechToTextService(Protocol):
    async def transcribe_stream(...) -> AsyncGenerator[dict, None]:
        ...

# Implementazioni
class WhisperService(SpeechToTextService):  # Open source
    ...

class GoogleSpeechService(SpeechToTextService):  # Cloud
    ...

# Factory
def get_speech_service() -> SpeechToTextService:
    provider = os.getenv("SPEECH_PROVIDER", "whisper")
    if provider == "whisper":
        return WhisperService()
    elif provider == "google":
        return GoogleSpeechService()
```

**Vantaggi**:
- ✅ Stesso codice per entrambi i provider
- ✅ Facile aggiungere nuovi provider
- ✅ Testabile (dependency injection)
- ✅ Zero vendor lock-in

---

## 🚀 Setup

### Opzione A: Open Source (Default) - €0/mese

#### 1. Hardware Requirements

**Minimo** (per testing):
- CPU: 4+ cores
- RAM: 8GB
- GPU: Opzionale (10x più veloce)

**Consigliato** (produzione):
- CPU: 8+ cores (Ryzen 7 / i7+)
- RAM: 16GB
- GPU: NVIDIA RTX 3060+ (12GB VRAM)
- Storage: 50GB SSD

**Costo stimato**:
- Server: €1,500-2,000 one-time
- Ammortizzato su 5 anni: €25-33/mese
- Energia: €10-20/mese
- **Totale: ~€40-50/mese FISSO**

#### 2. Install Dependencies

```bash
cd backend

# Install Python dependencies
pip install -r requirements.txt

# Download models (first time only)
python -c "from faster_whisper import WhisperModel; WhisperModel('large-v3')"
python -c "from transformers import AutoModel; AutoModel.from_pretrained('facebook/nllb-200-distilled-600M')"
```

#### 3. Configure Environment

```bash
# .env
SPEECH_PROVIDER=whisper
TRANSLATION_PROVIDER=nllb

# Optional: paths to fine-tuned models
WHISPER_MODEL_PATH=/models/whisper-large-v3-martial-arts
NLLB_MODEL_PATH=/models/nllb-martial-arts

# Terminology database
TERMINOLOGY_DB_PATH=/data/martial_arts_terminology.json
LEARNING_DB_PATH=/data/translation_corrections.json
```

#### 4. Test

```bash
# Start backend
python main.py

# Test providers
curl http://localhost:8000/live-translation/providers/info

# Expected response:
{
  "speech": {
    "provider": "whisper",
    "info": {
      "name": "OpenAI Whisper",
      "type": "open source",
      "cost": "self-hosted (no API costs)"
    }
  },
  "translation": {
    "provider": "nllb",
    "info": {
      "name": "Meta NLLB-200",
      "type": "open source",
      "cost": "self-hosted (no API costs)"
    }
  }
}
```

---

### Opzione B: Google Cloud (Optional) - ~€60-150/mese

#### 1. Google Cloud Setup

```bash
# Create project
gcloud projects create media-center-translation

# Enable APIs
gcloud services enable speech.googleapis.com
gcloud services enable translate.googleapis.com

# Create service account
gcloud iam service-accounts create media-center \
  --display-name="Media Center Translation"

# Grant permissions
gcloud projects add-iam-policy-binding YOUR_PROJECT_ID \
  --member="serviceAccount:media-center@YOUR_PROJECT_ID.iam.gserviceaccount.com" \
  --role="roles/speech.client"

gcloud projects add-iam-policy-binding YOUR_PROJECT_ID \
  --member="serviceAccount:media-center@YOUR_PROJECT_ID.iam.gserviceaccount.com" \
  --role="roles/cloudtranslate.user"

# Download key
gcloud iam service-accounts keys create ~/media-center-key.json \
  --iam-account=media-center@YOUR_PROJECT_ID.iam.gserviceaccount.com
```

#### 2. Configure Environment

```bash
# .env
SPEECH_PROVIDER=google
TRANSLATION_PROVIDER=google

GOOGLE_APPLICATION_CREDENTIALS=/path/to/media-center-key.json
GOOGLE_CLOUD_PROJECT=your-project-id
```

#### 3. Install Google Cloud Dependencies

```bash
pip install google-cloud-speech google-cloud-translate google-auth
```

---

### Opzione C: Hybrid (Best of Both Worlds)

```bash
# .env
SPEECH_PROVIDER=whisper    # Open source (€0)
TRANSLATION_PROVIDER=google # Google Cloud (alta qualità)

# OR

SPEECH_PROVIDER=google      # Google Cloud (alta qualità)
TRANSLATION_PROVIDER=nllb   # Open source con terminologia custom
```

---

## 🎯 Switching Providers

### Via API (Runtime)

```bash
# Switch to Google Cloud
curl -X POST http://localhost:8000/live-translation/providers/switch \
  -H "Authorization: Bearer ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "service_type": "speech",
    "provider": "google"
  }'

# Response:
{
  "message": "Provider switched to google",
  "note": "Restart application for changes to take full effect"
}
```

### Via Environment (.env)

```bash
# Edit .env
SPEECH_PROVIDER=google
TRANSLATION_PROVIDER=nllb

# Restart application
systemctl restart media-center-backend
```

### Via Code

```python
from services.live_translation.service_factory import switch_provider

# Switch provider
switch_provider("speech", "whisper")
switch_provider("translation", "nllb")
```

---

## 📊 Feature Comparison

### Whisper vs Google Speech-to-Text

| Feature | Whisper | Google Cloud |
|---------|---------|--------------|
| **Cost** | €0 (hardware only) | ~€1.44/hour |
| **Latency** | ~200-300ms | ~100-300ms |
| **Accuracy** | ~95% | ~95-98% |
| **Fine-tuning** | ✅ Yes (full control) | ❌ No |
| **Offline** | ✅ Yes | ❌ No (internet required) |
| **Privacy** | ✅ Data stays local | ⚠️ Sent to Google |
| **Languages** | 99+ | 100+ |
| **Hardware** | GPU recommended | Not needed |
| **Terminology** | ✅ Customizable | ⚠️ Limited |

**Whisper Pro**:
- Zero costi variabili
- Privacy (data locale)
- Fine-tunable per arti marziali
- Funziona offline

**Google Pro**:
- Nessun hardware da gestire
- Leggermente più accurato
- Auto-aggiornamenti

---

### NLLB vs Google Translation

| Feature | NLLB | Google Cloud |
|---------|------|--------------|
| **Cost** | €0 (hardware only) | ~€20/1M chars |
| **Latency** | ~50-150ms | ~50-150ms |
| **Accuracy** | ~90-95% | ~98% |
| **Fine-tuning** | ✅ Yes (full control) | ❌ No |
| **Offline** | ✅ Yes | ❌ No (internet required) |
| **Privacy** | ✅ Data stays local | ⚠️ Sent to Google |
| **Languages** | 200+ | 100+ |
| **Learning** | ✅ From user feedback | ❌ No |
| **Terminology** | ✅ Custom database | ❌ Generic |

**NLLB Pro**:
- Zero costi variabili
- Privacy (data locale)
- Fine-tunable per arti marziali
- **Learning system** (migliora con feedback)
- **Terminologia custom** (kata, kumite, etc.)
- Funziona offline

**Google Pro**:
- Nessun hardware da gestire
- Più accurato (testi generici)
- 100+ lingue

---

## 🤖 Learning System (Solo NLLB)

### Come Funziona

1. **Utente vede traduzione sbagliata**:
   - "Mettiti in guardia" → "Get into the watch" ❌

2. **Istruttore corregge**:
   - "Mettiti in guardia" → "Get into guard position" ✅

3. **Sistema impara**:
   - Salva correzione nel database
   - Applica automaticamente in futuro

### API per Correzioni

```python
from services.live_translation.nllb_service import get_nllb_service

nllb = get_nllb_service()

# Add correction
nllb.add_correction(
    source_text="Mettiti in guardia",
    source_lang="it",
    target_lang="en",
    wrong_translation="Get into the watch",
    corrected_text="Get into guard position",
    corrected_by="instructor_123"
)
```

### Statistiche Learning

```bash
curl http://localhost:8000/live-translation/learning/stats

# Response:
{
  "total_corrections": 156,
  "by_language": {
    "en": 89,
    "es": 34,
    "fr": 22,
    "de": 11
  },
  "recent_corrections": [...]
}
```

---

## 📚 Martial Arts Terminology Database

### Struttura

File: `backend/data/martial_arts_terminology.json`

```json
{
  "kata": {
    "it": "kata",
    "en": "kata",
    "es": "kata",
    "fr": "kata",
    "de": "Kata",
    "description": "Pre-arranged forms/patterns"
  },
  "guardia": {
    "it": "guardia",
    "en": "guard position",
    "es": "guardia",
    "fr": "garde",
    "de": "Stellung",
    "description": "Defensive stance"
  }
}
```

### Aggiungere Nuovi Termini

```bash
# Edit file
vim backend/data/martial_arts_terminology.json

# Add new term
{
  "nuovo_termine": {
    "it": "...",
    "en": "...",
    "es": "...",
    "fr": "...",
    "de": "...",
    "description": "..."
  }
}

# Restart application
systemctl restart media-center-backend
```

---

## 🎓 Fine-Tuning Models

### Fine-Tune Whisper (Advanced)

```bash
# Collect audio data
# - Record Italian martial arts classes
# - Transcribe manually (ground truth)
# - Create dataset

# Fine-tune
python scripts/fine_tune_whisper.py \
  --model large-v3 \
  --dataset martial_arts_audio/ \
  --output models/whisper-martial-arts

# Update .env
WHISPER_MODEL_PATH=/models/whisper-martial-arts
```

### Fine-Tune NLLB (Advanced)

```bash
# Collect parallel data
# - Italian martial arts texts
# - Translations in multiple languages

# Fine-tune
python scripts/fine_tune_nllb.py \
  --model facebook/nllb-200-distilled-600M \
  --dataset martial_arts_corpus/ \
  --output models/nllb-martial-arts

# Update .env
NLLB_MODEL_PATH=/models/nllb-martial-arts
```

---

## 💰 Cost Analysis

### Open Source (Default)

**One-time**:
- Server hardware: €1,500-2,000
- Setup time: 4-8 hours

**Monthly**:
- Hardware ammortization (5 anni): €25-33
- Energia elettrica: €10-20
- **Totale: ~€40-50/mese FISSO**

**Pro**:
- Costo fisso, prevedibile
- Nessun limite di utilizzo
- Privacy garantita
- Full control

---

### Google Cloud

**Monthly** (1 ora live/giorno):
- Speech-to-Text: 30h × €1.44 = €43
- Translation: ~€15
- **Totale: ~€60/mese VARIABILE**

**Monthly** (3 ore live/giorno):
- Speech-to-Text: 90h × €1.44 = €130
- Translation: ~€20
- **Totale: ~€150/mese VARIABILE**

**Pro**:
- No hardware
- Pay-as-you-go
- Auto-scaling
- Più accurato

---

### Hybrid Example

```bash
# Scenario: Open source speech + Google translation
SPEECH_PROVIDER=whisper      # €0
TRANSLATION_PROVIDER=google  # ~€15/mese

# Total: ~€15/mese + €40 hardware = €55/mese
# VS
# Full Google: ~€60-150/mese
```

---

## 🔧 Troubleshooting

### Provider Not Loading

```bash
# Check logs
tail -f /var/log/media-center/backend.log

# Expected:
# 🎤 Initializing speech service: whisper
# ✅ Whisper model loaded successfully (cuda, float16)
# 🌍 Initializing translation service: nllb
# ✅ NLLB model loaded successfully (cuda)
```

### GPU Not Detected

```bash
# Check CUDA
python -c "import torch; print(torch.cuda.is_available())"

# If False:
pip install torch torchvision torchaudio --index-url https://download.pytorch.org/whl/cu121
```

### Model Download Failed

```bash
# Manual download
huggingface-cli download facebook/nllb-200-distilled-600M
huggingface-cli download openai/whisper-large-v3
```

---

## 📈 Monitoring

### Provider Status

```bash
curl http://localhost:8000/live-translation/providers/info
```

### Performance Metrics

```python
# In Sentry dashboard:
# - Average latency per provider
# - Error rate
# - Usage statistics
```

---

## 🎯 Recommendations

### For You (ASD):
- **Use**: Whisper + NLLB (open source)
- **Why**:
  - Zero recurring costs
  - Privacy (data locale)
  - Fine-tunable per arti marziali
  - Learning da feedback istruttori
- **Hardware**: Invest in RTX 3060+ GPU

### For Small Clients:
- **Use**: Google Cloud
- **Why**:
  - No hardware investment
  - No maintenance
  - Pay only for usage
- **Cost**: €60-150/mese

### For Large Organizations:
- **Use**: Hybrid
  - Whisper (open source) per privacy
  - Google Translation per qualità massima
- **Cost**: €15-40/mese

---

## 📚 Next Steps

1. ✅ Choose provider (default: open source)
2. ✅ Install dependencies
3. ✅ Configure .env
4. ⏳ Test translation
5. ⏳ Add custom terminology
6. ⏳ Collect user corrections
7. ⏳ Fine-tune models (optional)

---

## 🔗 Resources

- **Whisper**: https://github.com/openai/whisper
- **Faster Whisper**: https://github.com/guillaumekln/faster-whisper
- **NLLB**: https://github.com/facebookresearch/fairseq/tree/nllb
- **Transformers**: https://huggingface.co/docs/transformers

---

**Status**: ✅ Production Ready
**Default**: Open Source (Whisper + NLLB)
**Optional**: Google Cloud
**Switchable**: Runtime or configuration

# RECAP SESSIONE - Media Center Arti Marziali
**Data: 29 Novembre 2025**

---

## ✅ COMPLETATO

### 1. Sistema Skeleton Extraction (Backend)
- Backend API `/api/v1/skeletons/extract` funzionante
- MediaPipe Pose integrato per estrazione landmarks
- Salvataggio JSON con 33 landmarks per frame
- Endpoint per recuperare skeleton esistenti

### 2. Sistema Donazioni/Stelline
- Modello database `Donation` con ripartizione 40/50/10
- API endpoints: `POST /donate`, `GET /wallet`, `GET /received`
- 40% autore, 50% piattaforma, 10% crew
- Integrato nel profilo utente

### 3. Skeleton Editor (Frontend)
- Pagina `/skeleton-editor/[id]`
- Visualizzazione landmarks su canvas
- Controlli playback (play/pause, velocità, frame-by-frame)
- UI con barra laterale landmarks

### 4. Skeleton Library (Frontend)
- Pagina `/skeleton-library`
- Griglia skeleton con preview
- Filtri per tipo/stile marziale
- Azioni: edit, download, delete

### 5. Traduzioni i18n Complete
- `it.json` e `en.json` aggiornati con:
  - `ingest`, `skeletonEditor`, `skeletonLibrary`
  - `donations`, `upload`, `monitor`
  - `voiceCloning`, `translation`, `livePlayer`, `error`

---

## ⚠️ DA FARE AL PROSSIMO AVVIO

### 1. Pulire cache frontend (OBBLIGATORIO)
```bash
cd C:\Users\utente\Desktop\GESTIONALI\media-center-arti-marziali\frontend
rmdir /s /q .next
npm run dev
```

### 2. Testare pagine
- `/skeleton-library` - Libreria skeleton
- `/skeleton-editor/[id]` - Editor
- `/ingest` - Upload con estrazione

### 3. Database (se necessario)
```bash
cd C:\Users\utente\Desktop\GESTIONALI\media-center-arti-marziali\backend
venv\Scripts\activate
alembic upgrade head
```

---

## 📁 FILE PRINCIPALI MODIFICATI

| Area | File |
|------|------|
| Backend | `routers/skeletons.py` |
| Backend | `models/donation.py` |
| Backend | `routers/donations.py` |
| Frontend | `app/skeleton-editor/[id]/page.tsx` |
| Frontend | `app/skeleton-library/page.tsx` |
| i18n | `locales/it.json` |
| i18n | `locales/en.json` |

---

## 🐛 ERRORE DA RISOLVERE

**Errore webpack all'avvio:**
```
TypeError: Cannot read properties of undefined (reading 'call')
```

**Causa:** Cache webpack corrotta durante le modifiche ai file

**Soluzione:** Eliminare la cartella `.next` e riavviare il dev server

---

## 📝 NOTE

- Il backend gira su porta 8100
- Il frontend gira su porta 3000
- MediaPipe richiede video in formato compatibile (mp4, webm)
- L'estrazione skeleton può richiedere tempo per video lunghi

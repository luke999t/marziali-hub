# 🌐 DOWNLOAD AUTOMATICO MATERIALE TEST
## Per Chrome Extension - Media Center Arti Marziali
## Data: 31 Gennaio 2026

---

# 🎯 ISTRUZIONI PER CHROME EXTENSION

**SE NON TROVI FILE DI TEST** nella cartella `test_data/`, scaricali automaticamente da queste fonti **LEGALI E GRATUITE**.

---

## 📚 LIBRI PDF (Pubblico Dominio - Archive.org)

### 1. Judo Kodokan (1915) - Con illustrazioni tecniche
```
URL: https://archive.org/details/judokodokan00kano
DOWNLOAD: https://archive.org/download/judokodokan00kano/judokodokan00kano.pdf
SALVA COME: test_data/judo_kodokan_1915.pdf
DIMENSIONE: ~15 MB
LINGUA: Inglese
CONTENUTO: 200+ pagine con tecniche judo illustrate
```

### 2. Jiu-Jitsu Combat Tricks (1904) - Immagini tecniche
```
URL: https://archive.org/details/jiujitsucombattr00hanc
DOWNLOAD: https://archive.org/download/jiujitsucombattr00hanc/jiujitsucombattr00hanc.pdf
SALVA COME: test_data/jiujitsu_1904.pdf
DIMENSIONE: ~8 MB
LINGUA: Inglese
CONTENUTO: Tecniche di difesa personale con foto
```

### 3. Complete Kano Jiu-Jitsu (1905)
```
URL: https://archive.org/details/completekanojiu00irvi
DOWNLOAD: https://archive.org/download/completekanojiu00irvi/completekanojiu00irvi.pdf
SALVA COME: test_data/kano_jiujitsu_1905.pdf
DIMENSIONE: ~20 MB
LINGUA: Inglese
CONTENUTO: Manuale completo con diagrammi
```

### 4. The Art of War - Sun Tzu (varie edizioni)
```
URL: https://archive.org/details/artofwar00telerich
DOWNLOAD: https://archive.org/download/artofwar00telerich/artofwar00telerich.pdf
SALVA COME: test_data/art_of_war.pdf
DIMENSIONE: ~5 MB
LINGUA: Inglese
CONTENUTO: Testo classico strategia marziale
```

---

## 🖼️ IMMAGINI TECNICHE (Wikimedia Commons - CC0/Public Domain)

### 1. Karate Kata Sequence
```
URL: https://commons.wikimedia.org/wiki/File:Goju-Ryu_Karate.svg
DOWNLOAD: https://upload.wikimedia.org/wikipedia/commons/thumb/8/8a/Goju-Ryu_Karate.svg/800px-Goju-Ryu_Karate.svg.png
SALVA COME: test_data/karate_kata_sequence.png
LICENZA: Public Domain
```

### 2. Judo Throw Position
```
URL: https://commons.wikimedia.org/wiki/File:Judo_throw.jpg
DOWNLOAD: https://upload.wikimedia.org/wikipedia/commons/thumb/4/4e/Judo_throw.jpg/640px-Judo_throw.jpg
SALVA COME: test_data/judo_throw.jpg
LICENZA: CC BY-SA
```

### 3. Tai Chi Form 24 - Posizione 13
```
URL: https://commons.wikimedia.org/wiki/File:Simplified_t%27ai_chi_ch%27uan_-_form_24_-_13.jpg
DOWNLOAD: https://upload.wikimedia.org/wikipedia/commons/thumb/5/5a/Simplified_t%27ai_chi_ch%27uan_-_form_24_-_13.jpg/480px-Simplified_t%27ai_chi_ch%27uan_-_form_24_-_13.jpg
SALVA COME: test_data/taichi_form24_pos13.jpg
LICENZA: CC BY-SA
```

### 4. Wing Chun Wooden Dummy
```
CERCA: https://commons.wikimedia.org/wiki/Category:Wing_Chun
SALVA COME: test_data/wingchun_dummy.jpg
```

### 5. Kung Fu Historical Illustration
```
URL: https://commons.wikimedia.org/wiki/Category:Kung_fu
CERCA: "martial artists" o "kung fu technique"
```

---

## 🎬 VIDEO (Creative Commons / Gratuiti)

### Opzione 1: Pexels (Gratuito, uso commerciale OK)
```
CERCA: https://www.pexels.com/search/videos/martial%20arts/
ESEMPI:
- Tai Chi in park
- Karate training
- Kung Fu demonstration

DOWNLOAD: Click su video → Download → HD
SALVA COME: test_data/martial_arts_demo.mp4
```

### Opzione 2: Pixabay (Gratuito, uso commerciale OK)
```
CERCA: https://pixabay.com/videos/search/martial%20arts/
DOWNLOAD: Click → Free Download
```

### Opzione 3: YouTube (SOLO con licenza Creative Commons!)
```
CERCA: "tai chi" site:youtube.com creative commons
FILTRO: Filters → Features → Creative Commons

NOTA: Verifica SEMPRE la licenza prima di usare!
Se licenza CC, usa yt-dlp:
yt-dlp -f "best[height<=720]" -o "test_data/video_cc.mp4" "URL"
```

---

## 🎤 AUDIO PER VOICE CLONING (Librivox - Public Domain)

### 1. Art of War - Audiobook (Inglese)
```
URL: https://librivox.org/the-art-of-war-by-sun-tzu/
DOWNLOAD: https://archive.org/download/art_of_war_librivox/art_of_war_01_sun_tzu_64kb.mp3
SALVA COME: test_data/audio_english_art_of_war.mp3
DURATA: ~5 minuti
LINGUA: Inglese

PER ESTRARRE 30 SECONDI (richiede ffmpeg):
ffmpeg -i test_data/audio_english_art_of_war.mp3 -ss 00:00:30 -t 00:00:30 test_data/audio_30s_sample.wav
```

### 2. Italiano - Cerca su Librivox
```
URL: https://librivox.org/search?primary_key=0&search_category=language&search_page=1&search_form=get_results&search_order=alpha&project_type=either&q=italiano
SCEGLI: Un audiobook italiano per test TTS italiano
```

---

## 📜 SCRIPT POWERSHELL AUTO-DOWNLOAD

Crea questo file ed eseguilo per scaricare tutto automaticamente:

```powershell
# File: download_test_data.ps1
# Posizione: media-center-arti-marziali\

$testDataPath = "C:\Users\utente\Desktop\GESTIONALI\media-center-arti-marziali\test_data"
New-Item -ItemType Directory -Force -Path $testDataPath | Out-Null

Write-Host "📥 Scaricando materiale di test da fonti legali..."
Write-Host ""

# 1. PDF - Judo Kodokan 1915
$url1 = "https://archive.org/download/judokodokan00kano/judokodokan00kano.pdf"
$out1 = "$testDataPath\judo_kodokan_1915.pdf"
if (-not (Test-Path $out1)) {
    Write-Host "  📚 Scaricando Judo Kodokan 1915 PDF..."
    try {
        Invoke-WebRequest -Uri $url1 -OutFile $out1 -UseBasicParsing -TimeoutSec 120
        Write-Host "     ✅ Completato"
    } catch {
        Write-Host "     ❌ Errore: $_"
    }
} else {
    Write-Host "  📚 Judo Kodokan già presente"
}

# 2. PDF - Jiu-Jitsu 1904
$url2 = "https://archive.org/download/jiujitsucombattr00hanc/jiujitsucombattr00hanc.pdf"
$out2 = "$testDataPath\jiujitsu_1904.pdf"
if (-not (Test-Path $out2)) {
    Write-Host "  📚 Scaricando Jiu-Jitsu 1904 PDF..."
    try {
        Invoke-WebRequest -Uri $url2 -OutFile $out2 -UseBasicParsing -TimeoutSec 120
        Write-Host "     ✅ Completato"
    } catch {
        Write-Host "     ❌ Errore: $_"
    }
} else {
    Write-Host "  📚 Jiu-Jitsu già presente"
}

# 3. Immagine Karate
$url3 = "https://upload.wikimedia.org/wikipedia/commons/thumb/8/8a/Goju-Ryu_Karate.svg/800px-Goju-Ryu_Karate.svg.png"
$out3 = "$testDataPath\karate_kata_sequence.png"
if (-not (Test-Path $out3)) {
    Write-Host "  🖼️ Scaricando immagine Karate..."
    try {
        Invoke-WebRequest -Uri $url3 -OutFile $out3 -UseBasicParsing
        Write-Host "     ✅ Completato"
    } catch {
        Write-Host "     ❌ Errore: $_"
    }
}

# 4. Immagine Tai Chi
$url4 = "https://upload.wikimedia.org/wikipedia/commons/thumb/5/5a/Simplified_t%27ai_chi_ch%27uan_-_form_24_-_13.jpg/480px-Simplified_t%27ai_chi_ch%27uan_-_form_24_-_13.jpg"
$out4 = "$testDataPath\taichi_form24.jpg"
if (-not (Test-Path $out4)) {
    Write-Host "  🖼️ Scaricando immagine Tai Chi..."
    try {
        Invoke-WebRequest -Uri $url4 -OutFile $out4 -UseBasicParsing
        Write-Host "     ✅ Completato"
    } catch {
        Write-Host "     ❌ Errore: $_"
    }
}

# 5. Immagine Judo
$url5 = "https://upload.wikimedia.org/wikipedia/commons/thumb/4/4e/Judo_throw.jpg/640px-Judo_throw.jpg"
$out5 = "$testDataPath\judo_throw.jpg"
if (-not (Test-Path $out5)) {
    Write-Host "  🖼️ Scaricando immagine Judo..."
    try {
        Invoke-WebRequest -Uri $url5 -OutFile $out5 -UseBasicParsing
        Write-Host "     ✅ Completato"
    } catch {
        Write-Host "     ❌ Errore: $_"
    }
}

# 6. Audio sample (Art of War - Librivox)
$url6 = "https://archive.org/download/art_of_war_librivox/art_of_war_01_sun_tzu_64kb.mp3"
$out6 = "$testDataPath\audio_english_sample.mp3"
if (-not (Test-Path $out6)) {
    Write-Host "  🎤 Scaricando audio sample inglese..."
    try {
        Invoke-WebRequest -Uri $url6 -OutFile $out6 -UseBasicParsing -TimeoutSec 60
        Write-Host "     ✅ Completato"
    } catch {
        Write-Host "     ❌ Errore: $_"
    }
}

Write-Host ""
Write-Host "═══════════════════════════════════════════════════════════"
Write-Host "✅ Download completato!"
Write-Host "═══════════════════════════════════════════════════════════"
Write-Host ""
Write-Host "File scaricati in: $testDataPath"
Write-Host ""
Get-ChildItem $testDataPath | Format-Table Name, @{N='Size (KB)';E={[math]::Round($_.Length/1KB,2)}} -AutoSize
```

---

## 🔍 COME USARE IN CHROME EXTENSION

### Se file mancanti:

1. **Opzione A - Manuale:**
   - Naviga agli URL sopra
   - Download manuale
   - Salva in `test_data/`

2. **Opzione B - Script:**
   - Copia script PowerShell
   - Esegui in terminale
   - Attendi completamento

3. **Opzione C - Skip test:**
   - Salta i test che richiedono file specifici
   - Annota come "SKIPPED - file mancante"

---

## ✅ CHECKLIST FILE NECESSARI

| File | Uso | Priorità | Fonte |
|------|-----|----------|-------|
| `*.pdf` (libro) | OCR, Knowledge extraction | 🔴 Alta | Archive.org |
| `*.jpg/*.png` (tecnica) | OCR immagini, Card generation | 🔴 Alta | Wikimedia |
| `*.mp4` (video) | Skeleton extraction, Fusion | 🟡 Media | Pexels/Pixabay |
| `*.mp3/*.wav` (audio) | Voice cloning, TTS | 🟡 Media | Librivox |

---

## 📜 LICENZE

| Fonte | Licenza | Uso Commerciale |
|-------|---------|-----------------|
| Archive.org (pre-1928) | Public Domain | ✅ Sì |
| Wikimedia Commons | CC0/CC-BY-SA | ✅ Sì (con attribuzione se CC-BY) |
| Librivox | Public Domain | ✅ Sì |
| Pexels | Pexels License | ✅ Sì |
| Pixabay | Pixabay License | ✅ Sì |

---

**IMPORTANTE:** Questi materiali sono SOLO per testing. Per produzione, usa contenuti originali o con licenza appropriata.

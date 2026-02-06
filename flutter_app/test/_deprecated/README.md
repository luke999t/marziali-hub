# TEST DEPRECATI - NON USARE

**Data deprecazione**: 11 Dicembre 2025
**Motivo**: Violazione LEGGE SUPREMA ZERO MOCK

## Contenuto

Questi test usavano mock per API/Repository:
- 302+ when/thenAnswer
- 383 MockClass usage
- Passano con backend SPENTO = FINTI

## Perche deprecati

I test con mock:
1. Non verificano comportamento REALE
2. Passano anche se il codice e rotto
3. Danno falsa sicurezza
4. Nascondono bug reali

## Sostituzione

Tutti i test sono stati riscritti in `test/real/` seguendo la LEGGE SUPREMA:
- Chiamano backend REALE su localhost:8000
- FALLISCONO se backend spento
- PASSANO solo se tutto funziona davvero

## Non usare questi test

```bash
# NON FARE QUESTO
flutter test test/_deprecated/

# FARE QUESTO
flutter test test/real/
```

## Archivio storico

Questi file sono mantenuti solo come riferimento storico.
Non devono essere eseguiti o usati come template.

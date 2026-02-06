"""
🎓 AI_MODULE: Test Manuale Overlay Render
🎓 AI_DESCRIPTION: Genera immagine di test con annotazioni per validazione visiva
🎓 AI_BUSINESS: Verifica che rendering produca output corretto prima di integrare
🎓 AI_TEACHING: Test manuale con dati fake, utile per debug visivo

📁 POSIZIONE: backend/scripts/test_overlay_render.py

💡 USAGE:
    cd backend
    python scripts/test_overlay_render.py
    
    Output: storage/overlays/test_render.png
"""

import sys
import os

# Aggiungi backend al path per import
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import cv2
import numpy as np
from pathlib import Path

# Import dal nostro modulo overlay
try:
    from services.overlay import OverlayRenderer, OverlayCalculator
    from services.overlay.schemas import (
        AngleAnnotation, TextAnnotation, HighlightAnnotation, ArrowAnnotation,
        AnchorPoint, ColorRGBA, Point2D, AnnotationType
    )
except ImportError as e:
    print(f"❌ Errore import: {e}")
    print("Assicurati di eseguire dallo directory 'backend'")
    sys.exit(1)


def create_fake_landmarks():
    """
    Crea landmarks fake per test.
    Simula una persona in piedi con braccia aperte.
    
    🎓 AI_TEACHING: MediaPipe Pose ha 33 landmarks.
    Coordinate normalizzate 0-1, origine top-left.
    """
    landmarks = []
    
    # Mappa posizioni (x, y normalizzate)
    positions = {
        0: (0.5, 0.15),    # nose
        1: (0.49, 0.13),   # left_eye_inner
        2: (0.47, 0.13),   # left_eye
        3: (0.45, 0.13),   # left_eye_outer
        4: (0.51, 0.13),   # right_eye_inner
        5: (0.53, 0.13),   # right_eye
        6: (0.55, 0.13),   # right_eye_outer
        7: (0.43, 0.15),   # left_ear
        8: (0.57, 0.15),   # right_ear
        9: (0.48, 0.18),   # mouth_left
        10: (0.52, 0.18),  # mouth_right
        11: (0.35, 0.30),  # left_shoulder
        12: (0.65, 0.30),  # right_shoulder
        13: (0.25, 0.45),  # left_elbow
        14: (0.75, 0.45),  # right_elbow
        15: (0.20, 0.60),  # left_wrist
        16: (0.80, 0.60),  # right_wrist
        17: (0.18, 0.62),  # left_pinky
        18: (0.82, 0.62),  # right_pinky
        19: (0.19, 0.61),  # left_index
        20: (0.81, 0.61),  # right_index
        21: (0.17, 0.60),  # left_thumb
        22: (0.83, 0.60),  # right_thumb
        23: (0.42, 0.55),  # left_hip
        24: (0.58, 0.55),  # right_hip
        25: (0.40, 0.72),  # left_knee
        26: (0.60, 0.72),  # right_knee
        27: (0.38, 0.90),  # left_ankle
        28: (0.62, 0.90),  # right_ankle
        29: (0.36, 0.92),  # left_heel
        30: (0.64, 0.92),  # right_heel
        31: (0.40, 0.95),  # left_foot_index
        32: (0.60, 0.95),  # right_foot_index
    }
    
    for i in range(33):
        x, y = positions.get(i, (0.5, 0.5))
        landmarks.append({
            "x": x,
            "y": y,
            "z": 0.0,
            "visibility": 1.0
        })
    
    return landmarks


def test_render():
    """
    Test principale: genera immagine con annotazioni.
    """
    print("🎨 Avvio test rendering overlay...")
    
    # Setup output directory
    output_dir = Path("storage/overlays")
    output_dir.mkdir(parents=True, exist_ok=True)
    
    # Dimensioni frame
    width, height = 1920, 1080
    
    # Crea frame di sfondo (grigio scuro invece che nero per vedere meglio)
    frame = np.full((height, width, 3), 30, dtype=np.uint8)
    
    # Aggiungi griglia per riferimento
    for x in range(0, width, 100):
        cv2.line(frame, (x, 0), (x, height), (50, 50, 50), 1)
    for y in range(0, height, 100):
        cv2.line(frame, (0, y), (width, y), (50, 50, 50), 1)
    
    # Landmarks fake
    landmarks = create_fake_landmarks()
    print(f"✅ Creati {len(landmarks)} landmarks fake")
    
    # Renderer
    renderer = OverlayRenderer(width, height)
    print(f"✅ Renderer inizializzato ({width}x{height})")
    
    # Disegna skeleton prima
    overlay = np.zeros((height, width, 4), dtype=np.uint8)
    renderer.render_skeleton(
        overlay, 
        landmarks,
        color=ColorRGBA(r=0, g=255, b=200, a=0.7),
        thickness=3,
        point_radius=6
    )
    
    frame_bgra = cv2.cvtColor(frame, cv2.COLOR_BGR2BGRA)
    frame_bgra = renderer._alpha_blend(frame_bgra, overlay)
    frame = cv2.cvtColor(frame_bgra, cv2.COLOR_BGRA2BGR)
    print("✅ Skeleton disegnato")
    
    # Annotazioni di test
    annotations = [
        # Angolo gomito sinistro
        AngleAnnotation(
            id="angle_left_elbow",
            type=AnnotationType.ANGLE,
            frame_index=0,
            point_a=AnchorPoint.LEFT_SHOULDER,
            vertex=AnchorPoint.LEFT_ELBOW,
            point_b=AnchorPoint.LEFT_WRIST,
            show_degrees=True,
            arc_radius=50,
            color=ColorRGBA(r=255, g=100, b=0, a=1.0),
            thickness=3,
            font_size=20
        ),
        
        # Angolo gomito destro
        AngleAnnotation(
            id="angle_right_elbow",
            type=AnnotationType.ANGLE,
            frame_index=0,
            point_a=AnchorPoint.RIGHT_SHOULDER,
            vertex=AnchorPoint.RIGHT_ELBOW,
            point_b=AnchorPoint.RIGHT_WRIST,
            show_degrees=True,
            arc_radius=50,
            color=ColorRGBA(r=255, g=100, b=0, a=1.0),
            thickness=3,
            font_size=20
        ),
        
        # Angolo ginocchio sinistro
        AngleAnnotation(
            id="angle_left_knee",
            type=AnnotationType.ANGLE,
            frame_index=0,
            point_a=AnchorPoint.LEFT_HIP,
            vertex=AnchorPoint.LEFT_KNEE,
            point_b=AnchorPoint.LEFT_ANKLE,
            show_degrees=True,
            arc_radius=40,
            color=ColorRGBA(r=0, g=200, b=255, a=1.0),
            thickness=3
        ),
        
        # Testo istruzione
        TextAnnotation(
            id="text_instruction",
            type=AnnotationType.TEXT,
            frame_index=0,
            text="Posizione di guardia",
            anchor=AnchorPoint.CENTER_SHOULDERS,
            offset_y=-80,
            font_size=32,
            color=ColorRGBA(r=255, g=255, b=255, a=1.0),
            background=True,
            background_color=ColorRGBA(r=0, g=0, b=0, a=0.7),
            padding=12
        ),
        
        # Highlight polso sinistro
        HighlightAnnotation(
            id="highlight_left_wrist",
            type=AnnotationType.HIGHLIGHT,
            frame_index=0,
            anchor=AnchorPoint.LEFT_WRIST,
            shape="circle",
            radius=35,
            color=ColorRGBA(r=255, g=255, b=0, a=0.9),
            thickness=3,
            filled=False
        ),
        
        # Highlight polso destro
        HighlightAnnotation(
            id="highlight_right_wrist",
            type=AnnotationType.HIGHLIGHT,
            frame_index=0,
            anchor=AnchorPoint.RIGHT_WRIST,
            shape="circle",
            radius=35,
            color=ColorRGBA(r=255, g=255, b=0, a=0.9),
            thickness=3,
            filled=False
        ),
        
        # Testo "Attenzione qui"
        TextAnnotation(
            id="text_attention",
            type=AnnotationType.TEXT,
            frame_index=0,
            text="Attenzione: gomito alto!",
            anchor=AnchorPoint.LEFT_ELBOW,
            offset_x=60,
            offset_y=-20,
            font_size=18,
            color=ColorRGBA(r=255, g=100, b=100, a=1.0),
            background=True,
            background_color=ColorRGBA(r=50, g=0, b=0, a=0.8),
            padding=8
        ),
    ]
    
    print(f"✅ Create {len(annotations)} annotazioni")
    
    # Renderizza annotazioni
    result = renderer.render_annotations(frame, annotations, landmarks)
    print("✅ Annotazioni renderizzate")
    
    # Aggiungi watermark
    cv2.putText(
        result,
        "Media Center Arti Marziali - Overlay Test",
        (20, height - 20),
        cv2.FONT_HERSHEY_SIMPLEX,
        0.6,
        (100, 100, 100),
        1,
        cv2.LINE_AA
    )
    
    # Salva risultato
    output_path = output_dir / "test_render.png"
    success = cv2.imwrite(str(output_path), result)
    
    if success:
        print(f"✅ Immagine salvata: {output_path}")
        print(f"   Dimensioni: {result.shape[1]}x{result.shape[0]}")
        print(f"   File size: {output_path.stat().st_size / 1024:.1f} KB")
    else:
        print(f"❌ Errore salvataggio immagine")
        return False
    
    # Verifica base
    assert result is not None, "Risultato nullo"
    assert result.shape == (height, width, 3), f"Shape errato: {result.shape}"
    assert output_path.exists(), "File non creato"
    
    print("\n" + "="*60)
    print("✅ TEST RENDERING COMPLETATO CON SUCCESSO!")
    print("="*60)
    print(f"\nApri il file per verificare visivamente:")
    print(f"   {output_path.absolute()}")
    
    return True


def test_calculator():
    """
    Test OverlayCalculator: verifica calcoli angoli.
    """
    print("\n🧮 Test Calculator...")
    
    calc = OverlayCalculator(1920, 1080)
    
    # Test angolo retto
    p1 = (100, 100)
    vertex = (100, 200)
    p2 = (200, 200)
    
    angle = calc.calculate_angle(p1, vertex, p2)
    print(f"   Angolo (90° atteso): {angle:.1f}°")
    assert 85 < angle < 95, f"Angolo dovrebbe essere ~90°, got {angle}"
    
    # Test angolo 180°
    p1 = (0, 100)
    vertex = (100, 100)
    p2 = (200, 100)
    
    angle = calc.calculate_angle(p1, vertex, p2)
    print(f"   Angolo (180° atteso): {angle:.1f}°")
    assert 175 < angle < 185, f"Angolo dovrebbe essere ~180°, got {angle}"
    
    # Test angolo 45°
    p1 = (100, 0)
    vertex = (100, 100)
    p2 = (200, 100)
    
    angle = calc.calculate_angle(p1, vertex, p2)
    print(f"   Angolo (90° atteso): {angle:.1f}°")
    assert 85 < angle < 95, f"Angolo dovrebbe essere ~90°, got {angle}"
    
    print("✅ Calculator test passed")


if __name__ == "__main__":
    # Fix encoding per Windows
    import sys
    if sys.platform == "win32":
        sys.stdout.reconfigure(encoding='utf-8', errors='replace')

    print("="*60)
    print("[MARTIAL ARTS] MEDIA CENTER - TEST OVERLAY RENDERING")
    print("="*60)

    try:
        test_calculator()
        test_render()
    except Exception as e:
        print(f"\n[ERROR] ERRORE: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

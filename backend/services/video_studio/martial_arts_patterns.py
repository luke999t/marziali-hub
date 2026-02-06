"""
🥋 Martial Arts Patterns Database
🥋 Pattern e caratteristiche per riconoscimento automatico stili

Supporta 5 stili:
1. Tai Chi (Chen, Yang, Wu)
2. Wing Chun
3. Shaolin Kung Fu
4. Bagua Zhang
5. Karate (Shotokan, Goju-Ryu)

Ogni pattern include:
- Landmarks chiave da analizzare
- Range angoli caratteristici
- Velocità movimento tipica
- Posizioni mani specifiche
- Transizioni comuni
"""

from typing import Dict, List, Any, Tuple
from dataclasses import dataclass
from enum import Enum

class MartialArtStyle(Enum):
    """Stili di arti marziali supportati"""
    TAI_CHI = "tai_chi"
    WING_CHUN = "wing_chun"
    SHAOLIN = "shaolin"
    BAGUA = "bagua"
    KARATE = "karate"
    UNKNOWN = "unknown"


@dataclass
class TechniquePattern:
    """Pattern per una tecnica specifica"""
    name: str
    style: MartialArtStyle
    description: str

    # Landmark requirements
    key_landmarks: List[int]  # Indici landmarks critici (su 75 totali)

    # Angoli caratteristici (gradi)
    angle_ranges: Dict[str, Tuple[float, float]]  # "joint_name": (min, max)

    # Velocità movimento
    velocity_profile: str  # "slow", "medium", "fast", "explosive", "gradual"

    # Posizioni mani
    hand_positions: Dict[str, str]  # "left": "open_palm", "right": "fist", etc.

    # Distanze relative
    distance_ratios: Dict[str, Tuple[float, float]]  # "shoulder_width": (0.8, 1.2)

    # Durata tipica (secondi)
    duration_range: Tuple[float, float]

    # Keywords per detection testuali
    keywords: List[str]

    # Pattern temporale
    temporal_signature: str  # "continuous", "discrete", "cyclic"

    # Confidence threshold per match
    confidence_threshold: float = 0.7


# ===============================================
# TAI CHI PATTERNS
# ===============================================

TAI_CHI_PATTERNS = {
    "yun_shou": TechniquePattern(
        name="云手 (Yun Shou - Cloud Hands)",
        style=MartialArtStyle.TAI_CHI,
        description="Movimento circolare continuo delle braccia, simbolo del Tai Chi",
        key_landmarks=[11, 12, 15, 16, 33, 34, 54, 55],  # Spalle, polsi, mani
        angle_ranges={
            "left_elbow": (90, 150),
            "right_elbow": (90, 150),
            "left_shoulder": (30, 120),
            "right_shoulder": (30, 120)
        },
        velocity_profile="slow",  # Molto lento e fluido
        hand_positions={
            "left": "open_palm_relaxed",
            "right": "open_palm_relaxed"
        },
        distance_ratios={
            "hands_distance": (0.5, 1.5),  # Mani sempre entro 1.5x larghezza spalle
            "center_alignment": (0.8, 1.2)  # Allineamento centrale
        },
        duration_range=(3.0, 8.0),  # Molto lento
        keywords=["yun shou", "cloud hands", "mani nuvola", "circular", "circolare"],
        temporal_signature="cyclic",  # Ripetitivo
        confidence_threshold=0.8
    ),

    "single_whip": TechniquePattern(
        name="单鞭 (Dan Bian - Single Whip)",
        style=MartialArtStyle.TAI_CHI,
        description="Posizione iconica con una mano a becco d'uccello",
        key_landmarks=[11, 12, 15, 16, 54, 55, 56, 57],  # Spalle, polsi, mani con dita
        angle_ranges={
            "left_shoulder": (70, 110),  # Braccio sinistro esteso
            "right_shoulder": (30, 60),   # Braccio destro piegato
            "left_elbow": (160, 180),     # Quasi dritto
            "right_elbow": (90, 130)
        },
        velocity_profile="gradual",
        hand_positions={
            "left": "hook_hand",  # Becco d'uccello (dita unite a punta)
            "right": "open_palm"
        },
        distance_ratios={
            "arm_span": (1.8, 2.2),  # Braccia molto allargate
            "stance_width": (1.0, 1.5)
        },
        duration_range=(2.0, 5.0),
        keywords=["single whip", "dan bian", "frusta", "whip", "becco"],
        temporal_signature="discrete",
        confidence_threshold=0.75
    ),

    "grasp_sparrows_tail": TechniquePattern(
        name="揽雀尾 (Lan Que Wei - Grasp Sparrow's Tail)",
        style=MartialArtStyle.TAI_CHI,
        description="Sequenza di 4 movimenti: Ward Off, Roll Back, Press, Push",
        key_landmarks=[11, 12, 13, 14, 15, 16, 33, 54],
        angle_ranges={
            "left_elbow": (100, 140),
            "right_elbow": (100, 140),
            "torso_rotation": (-30, 30)
        },
        velocity_profile="slow",
        hand_positions={
            "left": "curved_palm",
            "right": "curved_palm"
        },
        distance_ratios={
            "hands_vertical_offset": (0.1, 0.4),  # Mani a livelli diversi
            "center_distance": (0.3, 0.8)
        },
        duration_range=(8.0, 15.0),  # Sequenza lunga
        keywords=["lan que wei", "grasp sparrow", "ward off", "roll back", "press", "push"],
        temporal_signature="cyclic",
        confidence_threshold=0.7
    ),

    "push_hands": TechniquePattern(
        name="推手 (Tui Shou - Push Hands)",
        style=MartialArtStyle.TAI_CHI,
        description="Esercizio a due per sviluppare sensibilità",
        key_landmarks=[11, 12, 15, 16, 33, 54],  # Due persone
        angle_ranges={
            "elbow_angle": (90, 120),
            "shoulder_forward": (10, 40)
        },
        velocity_profile="slow",
        hand_positions={
            "left": "open_palm",
            "right": "open_palm"
        },
        distance_ratios={
            "contact_distance": (0.1, 0.3),  # Mani vicine (contatto)
            "body_distance": (0.5, 1.0)
        },
        duration_range=(5.0, 20.0),  # Esercizio continuo
        keywords=["push hands", "tui shou", "sticky hands", "sensing", "two person"],
        temporal_signature="cyclic",
        confidence_threshold=0.65
    )
}


# ===============================================
# WING CHUN PATTERNS
# ===============================================

WING_CHUN_PATTERNS = {
    "centerline_guard": TechniquePattern(
        name="守中线 (Centerline Guard)",
        style=MartialArtStyle.WING_CHUN,
        description="Guardia caratteristica con mani davanti al centro",
        key_landmarks=[11, 12, 15, 16, 33, 34, 54, 55],
        angle_ranges={
            "left_elbow": (90, 120),
            "right_elbow": (90, 120),
            "hands_vertical": (70, 110)  # Mani a livello petto
        },
        velocity_profile="medium",
        hand_positions={
            "left": "vertical_fist",  # Pugno verticale
            "right": "vertical_fist"
        },
        distance_ratios={
            "centerline_distance": (0.0, 0.2),  # Molto vicino al centro
            "hands_height": (0.6, 0.8),  # Altezza petto
            "elbow_in": (0.8, 1.0)  # Gomiti dentro
        },
        duration_range=(1.0, 10.0),  # Posizione statica o transizione
        keywords=["centerline", "guard", "man sao", "wu sao", "ready position"],
        temporal_signature="discrete",
        confidence_threshold=0.8
    ),

    "chain_punches": TechniquePattern(
        name="连环冲拳 (Chain Punches)",
        style=MartialArtStyle.WING_CHUN,
        description="Pugni rapidi consecutivi sulla centerline",
        key_landmarks=[13, 14, 15, 16, 54, 55],  # Gomiti e mani
        angle_ranges={
            "elbow_extension": (160, 180),  # Gomito quasi dritto
            "punch_angle": (0, 15)  # Pugno dritto avanti
        },
        velocity_profile="explosive",  # Molto veloce!
        hand_positions={
            "alternating": "vertical_fist"  # Pugni alternati
        },
        distance_ratios={
            "punch_distance": (1.0, 1.5),  # Estensione completa
            "rotation_minimal": (0.0, 0.1)  # Poca rotazione corpo
        },
        duration_range=(0.5, 2.0),  # Molto rapido
        keywords=["chain punch", "straight punch", "lian huan", "rapid fire"],
        temporal_signature="cyclic",  # Ripetitivo veloce
        confidence_threshold=0.75
    ),

    "tan_sao": TechniquePattern(
        name="摊手 (Tan Sao - Palm Up Block)",
        style=MartialArtStyle.WING_CHUN,
        description="Parata con palmo verso l'alto",
        key_landmarks=[11, 13, 15, 33],  # Braccio sinistro tipicamente
        angle_ranges={
            "elbow_angle": (100, 130),
            "wrist_rotation": (80, 100),  # Palmo su
            "shoulder_forward": (20, 50)
        },
        velocity_profile="fast",
        hand_positions={
            "executing_hand": "open_palm_up"
        },
        distance_ratios={
            "arm_extension": (0.6, 0.9),
            "elbow_centerline": (0.0, 0.2)
        },
        duration_range=(0.3, 1.0),
        keywords=["tan sao", "palm up", "dispersing hand", "block"],
        temporal_signature="discrete",
        confidence_threshold=0.7
    ),

    "bong_sao": TechniquePattern(
        name="膀手 (Bong Sao - Wing Arm)",
        style=MartialArtStyle.WING_CHUN,
        description="Parata con braccio a ala sollevato",
        key_landmarks=[11, 13, 15, 33],
        angle_ranges={
            "elbow_angle": (90, 110),  # Gomito piegato
            "shoulder_elevation": (60, 90),  # Braccio sollevato
            "elbow_out": (30, 60)  # Gomito fuori
        },
        velocity_profile="fast",
        hand_positions={
            "executing_hand": "open_palm_side"
        },
        distance_ratios={
            "elbow_height": (0.7, 0.9),  # Gomito alto
            "hand_position": (0.4, 0.6)
        },
        duration_range=(0.3, 1.0),
        keywords=["bong sao", "wing arm", "elbow up", "deflection"],
        temporal_signature="discrete",
        confidence_threshold=0.7
    ),

    "chi_sao": TechniquePattern(
        name="黐手 (Chi Sao - Sticky Hands)",
        style=MartialArtStyle.WING_CHUN,
        description="Esercizio di sensibilità con contatto continuo",
        key_landmarks=[11, 12, 13, 14, 15, 16, 33, 54],  # Entrambe le braccia
        angle_ranges={
            "contact_angle": (90, 120),
            "rolling_motion": (-45, 45)
        },
        velocity_profile="medium",
        hand_positions={
            "both": "contact_rolling"
        },
        distance_ratios={
            "arm_contact": (0.1, 0.3),  # Sempre in contatto
            "circular_motion": (0.3, 0.5)
        },
        duration_range=(5.0, 30.0),  # Esercizio continuo
        keywords=["chi sao", "sticky hands", "sensitivity", "rolling", "two person"],
        temporal_signature="cyclic",
        confidence_threshold=0.65
    )
}


# ===============================================
# SHAOLIN PATTERNS
# ===============================================

SHAOLIN_PATTERNS = {
    "tiger_claw": TechniquePattern(
        name="虎爪 (Hu Zhua - Tiger Claw)",
        style=MartialArtStyle.SHAOLIN,
        description="Artiglio di tigre con dita curve",
        key_landmarks=[15, 16, 33, 34, 54, 55],  # Polsi e mani
        angle_ranges={
            "fingers_curl": (60, 90),  # Dita piegate
            "wrist_tension": (10, 30),
            "elbow_angle": (120, 160)
        },
        velocity_profile="explosive",
        hand_positions={
            "both": "claw_shape"  # Dita separate e curve
        },
        distance_ratios={
            "claw_spread": (0.15, 0.25),  # Dita allargate
            "strike_distance": (0.8, 1.2)
        },
        duration_range=(0.5, 1.5),
        keywords=["tiger claw", "hu zhua", "claw", "grab", "tiger"],
        temporal_signature="discrete",
        confidence_threshold=0.75
    ),

    "dragon_fist": TechniquePattern(
        name="龙拳 (Long Quan - Dragon Fist)",
        style=MartialArtStyle.SHAOLIN,
        description="Pugno del drago con forma speciale",
        key_landmarks=[15, 16, 54, 55],
        angle_ranges={
            "fist_formation": (15, 30),  # Nocche speciali
            "wrist_straight": (170, 180),
            "punch_spiral": (10, 30)  # Rotazione
        },
        velocity_profile="explosive",
        hand_positions={
            "executing": "dragon_fist"  # Forma specifica
        },
        distance_ratios={
            "extension_full": (0.9, 1.1),
            "body_twist": (0.3, 0.6)
        },
        duration_range=(0.3, 0.8),
        keywords=["dragon fist", "long quan", "spiral", "phoenix eye"],
        temporal_signature="discrete",
        confidence_threshold=0.7
    ),

    "buddha_palm": TechniquePattern(
        name="佛掌 (Fo Zhang - Buddha Palm)",
        style=MartialArtStyle.SHAOLIN,
        description="Palmo aperto potente",
        key_landmarks=[15, 16, 33, 54],
        angle_ranges={
            "palm_open": (170, 180),  # Completamente aperto
            "fingers_together": (0, 10),
            "wrist_firm": (170, 180)
        },
        velocity_profile="explosive",
        hand_positions={
            "striking": "open_palm_firm"
        },
        distance_ratios={
            "palm_strike": (0.8, 1.1),
            "body_power": (0.5, 0.8)
        },
        duration_range=(0.4, 1.0),
        keywords=["buddha palm", "fo zhang", "palm strike", "open hand"],
        temporal_signature="discrete",
        confidence_threshold=0.75
    ),

    "monkey_stance": TechniquePattern(
        name="猴式 (Hou Shi - Monkey Stance)",
        style=MartialArtStyle.SHAOLIN,
        description="Posizione bassa imitando la scimmia",
        key_landmarks=[23, 24, 25, 26, 27, 28],  # Anche, ginocchia, caviglie
        angle_ranges={
            "knee_bend": (60, 90),  # Molto piegato
            "hip_low": (30, 60),    # Posizione bassa
            "back_curve": (20, 40)
        },
        velocity_profile="fast",  # Movimenti agili
        hand_positions={
            "both": "relaxed_claw"
        },
        distance_ratios={
            "stance_low": (0.4, 0.6),  # Molto basso
            "agile_movement": (0.5, 1.0)
        },
        duration_range=(1.0, 3.0),
        keywords=["monkey", "hou", "low stance", "agile", "animal form"],
        temporal_signature="discrete",
        confidence_threshold=0.7
    ),

    "crane_kick": TechniquePattern(
        name="鹤腿 (He Tui - Crane Kick)",
        style=MartialArtStyle.SHAOLIN,
        description="Calcio alto su una gamba come la gru",
        key_landmarks=[23, 24, 25, 26, 27, 28],  # Gambe
        angle_ranges={
            "standing_leg": (170, 180),  # Gamba d'appoggio dritta
            "kicking_leg": (90, 150),    # Calcio alto
            "hip_flexibility": (60, 120)
        },
        velocity_profile="explosive",
        hand_positions={
            "both": "wings_extended"  # Braccia come ali
        },
        distance_ratios={
            "kick_height": (0.8, 1.2),  # Calcio alto
            "balance": (0.9, 1.0)
        },
        duration_range=(0.5, 1.5),
        keywords=["crane kick", "he tui", "high kick", "bird", "one leg"],
        temporal_signature="discrete",
        confidence_threshold=0.75
    )
}


# ===============================================
# BAGUA ZHANG PATTERNS
# ===============================================

BAGUA_PATTERNS = {
    "circle_walking": TechniquePattern(
        name="走圈 (Zou Quan - Circle Walking)",
        style=MartialArtStyle.BAGUA,
        description="Camminata circolare caratteristica del Bagua",
        key_landmarks=[23, 24, 25, 26, 27, 28, 11, 12],  # Gambe + spalle
        angle_ranges={
            "circle_arc": (30, 60),  # Curvatura percorso
            "knee_bend": (120, 140),
            "torso_twist": (20, 45)  # Torsione corpo
        },
        velocity_profile="medium",  # Velocità costante
        hand_positions={
            "both": "palms_changing"  # Mani cambiano continuamente
        },
        distance_ratios={
            "circle_radius": (1.0, 2.0),  # Cerchio medio-grande
            "steps_small": (0.3, 0.5)
        },
        duration_range=(5.0, 30.0),  # Camminata continua
        keywords=["circle walk", "zou quan", "walking", "circular", "bagua"],
        temporal_signature="cyclic",
        confidence_threshold=0.8
    ),

    "palm_changes": TechniquePattern(
        name="换掌 (Huan Zhang - Palm Changes)",
        style=MartialArtStyle.BAGUA,
        description="Cambi di palmo durante la camminata",
        key_landmarks=[11, 12, 15, 16, 33, 54],
        angle_ranges={
            "palm_rotation": (90, 180),  # Rotazione completa
            "elbow_flow": (90, 150),
            "body_spiral": (30, 90)
        },
        velocity_profile="gradual",  # Fluido
        hand_positions={
            "alternating": "palm_transitions"
        },
        distance_ratios={
            "palm_distance": (0.5, 1.0),
            "spiral_motion": (0.4, 0.8)
        },
        duration_range=(2.0, 5.0),
        keywords=["palm change", "huan zhang", "transition", "flow"],
        temporal_signature="cyclic",
        confidence_threshold=0.7
    ),

    "snake_palm": TechniquePattern(
        name="蛇掌 (She Zhang - Snake Palm)",
        style=MartialArtStyle.BAGUA,
        description="Palmo serpeggiante con movimento ondulatorio",
        key_landmarks=[15, 16, 33, 54],
        angle_ranges={
            "wrist_wave": (30, 60),  # Movimento ondulatorio
            "fingers_together": (0, 10),
            "strike_angle": (15, 45)
        },
        velocity_profile="fast",
        hand_positions={
            "striking": "snake_palm"  # Dita unite, ondulante
        },
        distance_ratios={
            "wave_motion": (0.3, 0.6),
            "penetration": (0.8, 1.1)
        },
        duration_range=(0.5, 1.5),
        keywords=["snake palm", "she zhang", "wave", "penetrating"],
        temporal_signature="discrete",
        confidence_threshold=0.7
    ),

    "lion_palm": TechniquePattern(
        name="狮掌 (Shi Zhang - Lion Palm)",
        style=MartialArtStyle.BAGUA,
        description="Palmo del leone potente",
        key_landmarks=[11, 15, 33, 54],
        angle_ranges={
            "palm_strike": (170, 180),
            "shoulder_power": (40, 80),
            "body_behind": (0.5, 0.8)
        },
        velocity_profile="explosive",
        hand_positions={
            "striking": "heavy_palm"
        },
        distance_ratios={
            "full_extension": (0.9, 1.1),
            "weight_transfer": (0.7, 1.0)
        },
        duration_range=(0.4, 1.0),
        keywords=["lion palm", "shi zhang", "heavy strike", "power"],
        temporal_signature="discrete",
        confidence_threshold=0.75
    )
}


# ===============================================
# KARATE PATTERNS
# ===============================================

KARATE_PATTERNS = {
    "zenkutsu_dachi": TechniquePattern(
        name="前屈立ち (Zenkutsu Dachi - Front Stance)",
        style=MartialArtStyle.KARATE,
        description="Posizione fondamentale in avanti",
        key_landmarks=[23, 24, 25, 26, 27, 28],
        angle_ranges={
            "front_knee": (90, 110),   # Ginocchio anteriore piegato
            "back_leg": (160, 180),    # Gamba posteriore dritta
            "stance_length": (1.5, 2.0)
        },
        velocity_profile="medium",
        hand_positions={
            "guard": "chamber_fist"
        },
        distance_ratios={
            "wide_stance": (1.5, 2.0),
            "weight_forward": (0.6, 0.7)
        },
        duration_range=(1.0, 5.0),
        keywords=["zenkutsu", "front stance", "forward stance"],
        temporal_signature="discrete",
        confidence_threshold=0.8
    ),

    "oi_zuki": TechniquePattern(
        name="追い突き (Oi Zuki - Lunge Punch)",
        style=MartialArtStyle.KARATE,
        description="Pugno in avanzamento",
        key_landmarks=[13, 14, 15, 16, 23, 25, 27],  # Braccio + gamba avanti
        angle_ranges={
            "punch_extension": (170, 180),
            "hip_rotation": (30, 60),
            "front_step": (90, 120)
        },
        velocity_profile="explosive",
        hand_positions={
            "punching": "horizontal_fist",
            "chamber": "hip_fist"
        },
        distance_ratios={
            "full_extension": (0.95, 1.05),
            "hip_snap": (0.5, 0.8)
        },
        duration_range=(0.3, 0.8),
        keywords=["oi zuki", "lunge punch", "stepping punch"],
        temporal_signature="discrete",
        confidence_threshold=0.75
    ),

    "mae_geri": TechniquePattern(
        name="前蹴り (Mae Geri - Front Kick)",
        style=MartialArtStyle.KARATE,
        description="Calcio frontale con palla del piede",
        key_landmarks=[23, 25, 27, 31],  # Anca, ginocchio, caviglia, piede
        angle_ranges={
            "knee_chamber": (45, 60),   # Camera ginocchio
            "kick_extension": (150, 180),
            "hip_thrust": (10, 30)
        },
        velocity_profile="explosive",
        hand_positions={
            "both": "guard_position"
        },
        distance_ratios={
            "kick_height": (0.6, 1.0),  # Medio-alto
            "balance": (0.9, 1.0)
        },
        duration_range=(0.4, 1.0),
        keywords=["mae geri", "front kick", "snap kick"],
        temporal_signature="discrete",
        confidence_threshold=0.75
    ),

    "uke": TechniquePattern(
        name="受け (Uke - Block)",
        style=MartialArtStyle.KARATE,
        description="Parata con avambraccio",
        key_landmarks=[13, 14, 15, 16],
        angle_ranges={
            "forearm_angle": (90, 120),
            "chamber_to_block": (60, 90),
            "hip_rotation": (20, 45)
        },
        velocity_profile="fast",
        hand_positions={
            "blocking": "tight_fist"
        },
        distance_ratios={
            "block_distance": (0.4, 0.7),
            "body_protection": (0.2, 0.4)
        },
        duration_range=(0.2, 0.6),
        keywords=["uke", "block", "parry", "age uke", "gedan barai"],
        temporal_signature="discrete",
        confidence_threshold=0.7
    ),

    "kata_stance": TechniquePattern(
        name="型構え (Kata Stance)",
        style=MartialArtStyle.KARATE,
        description="Posizioni formali del kata",
        key_landmarks=[23, 24, 25, 26, 11, 12],
        angle_ranges={
            "precise_angles": (80, 100),  # Angoli precisi
            "stable_base": (90, 110),
            "formal_posture": (170, 180)
        },
        velocity_profile="slow",  # Posizioni tenute
        hand_positions={
            "formal": "precise_placement"
        },
        distance_ratios={
            "stance_perfect": (0.95, 1.05),  # Molto preciso
            "symmetry": (0.98, 1.02)
        },
        duration_range=(2.0, 10.0),
        keywords=["kata", "form", "heian", "tekki", "bassai"],
        temporal_signature="discrete",
        confidence_threshold=0.8
    )
}


# ===============================================
# DATABASE COMPLETO
# ===============================================

MARTIAL_ARTS_DATABASE = {
    MartialArtStyle.TAI_CHI: TAI_CHI_PATTERNS,
    MartialArtStyle.WING_CHUN: WING_CHUN_PATTERNS,
    MartialArtStyle.SHAOLIN: SHAOLIN_PATTERNS,
    MartialArtStyle.BAGUA: BAGUA_PATTERNS,
    MartialArtStyle.KARATE: KARATE_PATTERNS
}


# ===============================================
# UTILITY FUNCTIONS
# ===============================================

def get_all_patterns() -> Dict[str, TechniquePattern]:
    """Restituisce tutti i pattern di tutti gli stili"""
    all_patterns = {}
    for style_patterns in MARTIAL_ARTS_DATABASE.values():
        all_patterns.update(style_patterns)
    return all_patterns


def get_patterns_by_style(style: MartialArtStyle) -> Dict[str, TechniquePattern]:
    """Restituisce pattern per uno stile specifico"""
    return MARTIAL_ARTS_DATABASE.get(style, {})


def get_pattern_by_name(pattern_name: str) -> TechniquePattern:
    """Cerca un pattern per nome"""
    all_patterns = get_all_patterns()
    return all_patterns.get(pattern_name, None)


def search_patterns_by_keyword(keyword: str) -> List[TechniquePattern]:
    """Cerca pattern che contengono una keyword"""
    results = []
    all_patterns = get_all_patterns()

    keyword_lower = keyword.lower()
    for pattern in all_patterns.values():
        if any(keyword_lower in kw.lower() for kw in pattern.keywords):
            results.append(pattern)

    return results


def get_style_characteristics(style: MartialArtStyle) -> Dict[str, Any]:
    """Restituisce caratteristiche generali di uno stile"""
    characteristics = {
        MartialArtStyle.TAI_CHI: {
            "speed": "slow",
            "power": "internal",
            "movement": "circular_flowing",
            "philosophy": "softness_overcomes_hardness",
            "typical_features": ["slow_motion", "continuous_flow", "circular_arms", "rooted_stance"]
        },
        MartialArtStyle.WING_CHUN: {
            "speed": "fast",
            "power": "explosive_short",
            "movement": "direct_linear",
            "philosophy": "economy_of_motion",
            "typical_features": ["centerline_control", "chain_punches", "sticky_hands", "close_range"]
        },
        MartialArtStyle.SHAOLIN: {
            "speed": "varied",
            "power": "external_explosive",
            "movement": "dynamic_acrobatic",
            "philosophy": "strength_and_flexibility",
            "typical_features": ["animal_forms", "high_kicks", "acrobatics", "powerful_strikes"]
        },
        MartialArtStyle.BAGUA: {
            "speed": "medium_flowing",
            "power": "internal_spiral",
            "movement": "circular_walking",
            "philosophy": "constant_change",
            "typical_features": ["circle_walking", "palm_changes", "spiraling", "evasive"]
        },
        MartialArtStyle.KARATE: {
            "speed": "explosive",
            "power": "external_focused",
            "movement": "linear_direct",
            "philosophy": "precision_and_power",
            "typical_features": ["formal_stances", "kiai", "kihon_basics", "kata_forms"]
        }
    }

    return characteristics.get(style, {})


# ===============================================
# PATTERN STATISTICS
# ===============================================

def get_database_stats() -> Dict[str, Any]:
    """Restituisce statistiche del database"""
    stats = {
        "total_styles": len(MARTIAL_ARTS_DATABASE),
        "total_patterns": sum(len(patterns) for patterns in MARTIAL_ARTS_DATABASE.values()),
        "patterns_per_style": {
            style.value: len(patterns)
            for style, patterns in MARTIAL_ARTS_DATABASE.items()
        }
    }
    return stats


if __name__ == "__main__":
    # Test database
    print("🥋 Martial Arts Patterns Database")
    print("="*50)

    stats = get_database_stats()
    print(f"\nDatabase Statistics:")
    print(f"  Total Styles: {stats['total_styles']}")
    print(f"  Total Patterns: {stats['total_patterns']}")
    print(f"\nPatterns per Style:")
    for style, count in stats['patterns_per_style'].items():
        print(f"  {style}: {count} patterns")

    print(f"\nExample: Tai Chi Yun Shou Pattern:")
    yun_shou = get_pattern_by_name("yun_shou")
    if yun_shou:
        print(f"  Name: {yun_shou.name}")
        print(f"  Description: {yun_shou.description}")
        print(f"  Velocity: {yun_shou.velocity_profile}")
        print(f"  Duration: {yun_shou.duration_range[0]}-{yun_shou.duration_range[1]}s")

    print(f"\nSearch 'punch' patterns:")
    punch_patterns = search_patterns_by_keyword("punch")
    for pattern in punch_patterns:
        print(f"  - {pattern.name} ({pattern.style.value})")

"""
AI_MODULE: Avatar Service
AI_DESCRIPTION: Business logic per gestione avatar 3D e bone mapping MediaPipe->Avatar
AI_TEACHING: Il mapping landmarks->bones e' il cuore del sistema avatar.
             MediaPipe Holistic produce 75 landmarks (33 pose + 21 left hand + 21 right hand).
             Ogni landmark ha coordinate (x, y, z) normalizzate [0,1].
             Per animare l'avatar, calcoliamo rotazioni bone da posizioni relative
             tra landmarks padre-figlio usando quaternioni.
"""

import math
import logging
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from uuid import UUID

logger = logging.getLogger(__name__)

# Path base per storage avatar
AVATAR_STORAGE_PATH = Path(__file__).parent.parent / "storage" / "avatars"


class AvatarService:
    """
    Service per gestione avatar 3D e mapping bone MediaPipe.

    WHY service separato dal router:
    - Testabilita': logica pura senza dipendenze HTTP
    - Riusabilita': puo' essere usato da CLI, background jobs, etc.
    - Separazione concerns: router gestisce HTTP, service gestisce logica
    """

    # =========================================================================
    # MAPPING MEDIAPIPE HOLISTIC -> READYPLAYERME BONES
    # =========================================================================
    #
    # MediaPipe Holistic produce 3 set di landmarks:
    # 1. Pose: 33 landmarks per corpo (indici 0-32)
    # 2. Left Hand: 21 landmarks (indici 33-53 nel nostro sistema unificato)
    # 3. Right Hand: 21 landmarks (indici 54-74 nel nostro sistema unificato)
    #
    # ReadyPlayerMe usa naming convention Mixamo-compatible.
    # Non tutti i 75 landmarks mappano 1:1 su bones - alcuni landmarks
    # servono come riferimento per calcolare rotazioni (es. spalle per torso).
    # =========================================================================

    BODY_MAPPING: Dict[int, str] = {
        # Testa e collo
        0: "Head",              # nose - direzione testa
        # 1-4: occhi (non mappati su bones)
        # 5-6: orecchie (non mappati)
        # 7-10: bocca (non mappati)
        11: "LeftShoulder",     # left_shoulder
        12: "RightShoulder",    # right_shoulder
        13: "LeftArm",          # left_elbow
        14: "RightArm",        # right_elbow
        15: "LeftForeArm",     # left_wrist
        16: "RightForeArm",    # right_wrist
        # 17-22: mani base (gestiti dal hand tracking dedicato)
        23: "LeftUpLeg",       # left_hip
        24: "RightUpLeg",      # right_hip
        25: "LeftLeg",         # left_knee
        26: "RightLeg",       # right_knee
        27: "LeftFoot",        # left_ankle
        28: "RightFoot",      # right_ankle
        29: "LeftToeBase",     # left_heel
        30: "RightToeBase",   # right_heel
        31: "LeftToe_End",    # left_foot_index
        32: "RightToe_End",   # right_foot_index
    }

    LEFT_HAND_MAPPING: Dict[int, str] = {
        # MediaPipe Hand landmarks (0-20)
        0: "LeftHand",           # wrist
        1: "LeftHandThumb1",     # thumb_cmc
        2: "LeftHandThumb2",     # thumb_mcp
        3: "LeftHandThumb3",     # thumb_ip
        4: "LeftHandThumb4",     # thumb_tip
        5: "LeftHandIndex1",     # index_mcp
        6: "LeftHandIndex2",     # index_pip
        7: "LeftHandIndex3",     # index_dip
        8: "LeftHandIndex4",     # index_tip
        9: "LeftHandMiddle1",    # middle_mcp
        10: "LeftHandMiddle2",   # middle_pip
        11: "LeftHandMiddle3",   # middle_dip
        12: "LeftHandMiddle4",   # middle_tip
        13: "LeftHandRing1",     # ring_mcp
        14: "LeftHandRing2",     # ring_pip
        15: "LeftHandRing3",     # ring_dip
        16: "LeftHandRing4",     # ring_tip
        17: "LeftHandPinky1",    # pinky_mcp
        18: "LeftHandPinky2",    # pinky_pip
        19: "LeftHandPinky3",    # pinky_dip
        20: "LeftHandPinky4",    # pinky_tip
    }

    RIGHT_HAND_MAPPING: Dict[int, str] = {
        0: "RightHand",
        1: "RightHandThumb1",
        2: "RightHandThumb2",
        3: "RightHandThumb3",
        4: "RightHandThumb4",
        5: "RightHandIndex1",
        6: "RightHandIndex2",
        7: "RightHandIndex3",
        8: "RightHandIndex4",
        9: "RightHandMiddle1",
        10: "RightHandMiddle2",
        11: "RightHandMiddle3",
        12: "RightHandMiddle4",
        13: "RightHandRing1",
        14: "RightHandRing2",
        15: "RightHandRing3",
        16: "RightHandRing4",
        17: "RightHandPinky1",
        18: "RightHandPinky2",
        19: "RightHandPinky3",
        20: "RightHandPinky4",
    }

    def get_bone_mapping(self) -> dict:
        """
        Ritorna il mapping completo MediaPipe -> Avatar bones.

        WHY 3 dizionari separati: MediaPipe Holistic ritorna i landmarks
        in 3 array separati (pose_landmarks, left_hand_landmarks, right_hand_landmarks).
        Il frontend deve sapere quale array usare per quale set di bones.
        """
        total_bones = (
            len(self.BODY_MAPPING) +
            len(self.LEFT_HAND_MAPPING) +
            len(self.RIGHT_HAND_MAPPING)
        )
        return {
            "body": self.BODY_MAPPING,
            "left_hand": self.LEFT_HAND_MAPPING,
            "right_hand": self.RIGHT_HAND_MAPPING,
            "total_landmarks": 75,
            "total_bones": total_bones,
        }

    async def apply_skeleton_to_avatar(
        self,
        avatar_id: UUID,
        skeleton_data: dict,
        frame_number: Optional[int] = None,
    ) -> dict:
        """
        Converte skeleton MediaPipe (75 landmarks) in bone transforms per avatar.

        ALGORITMO:
        1. Per ogni frame del skeleton (o solo frame_number se specificato)
        2. Per ogni coppia parent-child landmark con mapping definito
        3. Calcola la rotazione del bone dalla posizione relativa dei landmarks
        4. Output: lista di transforms per animazione avatar

        WHY quaternioni e non euler angles:
        - No gimbal lock (blocco rotazione a certe angolazioni)
        - Interpolazione smooth tra frame (SLERP)
        - Standard de facto per animazione 3D
        """
        frames = skeleton_data.get("frames", [])
        if not frames:
            logger.warning(f"No frames in skeleton data for avatar {avatar_id}")
            return {
                "avatar_id": str(avatar_id),
                "skeleton_id": skeleton_data.get("skeleton_id", ""),
                "frame_count": 0,
                "bone_transforms": [],
            }

        # Se richiesto un frame specifico, filtra
        if frame_number is not None:
            if 0 <= frame_number < len(frames):
                frames = [frames[frame_number]]
            else:
                logger.error(f"Frame {frame_number} out of range (0-{len(frames)-1})")
                return {
                    "avatar_id": str(avatar_id),
                    "skeleton_id": skeleton_data.get("skeleton_id", ""),
                    "frame_count": 0,
                    "bone_transforms": [],
                }

        all_transforms = []
        for frame in frames:
            frame_transforms = {}

            # Processa body landmarks (pose)
            pose_landmarks = frame.get("pose_landmarks", [])
            if pose_landmarks:
                frame_transforms.update(
                    self._process_body_landmarks(pose_landmarks)
                )

            # Processa left hand landmarks
            left_hand_landmarks = frame.get("left_hand_landmarks", [])
            if left_hand_landmarks:
                frame_transforms.update(
                    self._process_hand_landmarks(left_hand_landmarks, "left")
                )

            # Processa right hand landmarks
            right_hand_landmarks = frame.get("right_hand_landmarks", [])
            if right_hand_landmarks:
                frame_transforms.update(
                    self._process_hand_landmarks(right_hand_landmarks, "right")
                )

            all_transforms.append(frame_transforms)

        return {
            "avatar_id": str(avatar_id),
            "skeleton_id": skeleton_data.get("skeleton_id", ""),
            "frame_count": len(all_transforms),
            "bone_transforms": all_transforms,
        }

    def _process_body_landmarks(self, landmarks: List[dict]) -> Dict[str, dict]:
        """
        Calcola transforms per i bones del corpo dai pose landmarks.

        WHY bones come coppie parent-child:
        Un bone in un rig 3D connette due articolazioni.
        Es: il bone "LeftArm" va dalla spalla al gomito.
        La sua rotazione si calcola dalla direzione spalla->gomito.
        """
        transforms = {}

        # Coppie (parent_idx, child_idx) per calcolo direzione bone
        bone_pairs = [
            (11, 13, "LeftArm"),       # spalla -> gomito
            (13, 15, "LeftForeArm"),   # gomito -> polso
            (12, 14, "RightArm"),
            (14, 16, "RightForeArm"),
            (23, 25, "LeftUpLeg"),     # anca -> ginocchio
            (25, 27, "LeftLeg"),       # ginocchio -> caviglia
            (24, 26, "RightUpLeg"),
            (26, 28, "RightLeg"),
            (27, 31, "LeftFoot"),      # caviglia -> punta piede
            (28, 32, "RightFoot"),
        ]

        for parent_idx, child_idx, bone_name in bone_pairs:
            if parent_idx < len(landmarks) and child_idx < len(landmarks):
                parent = landmarks[parent_idx]
                child = landmarks[child_idx]

                parent_pos = (parent.get("x", 0), parent.get("y", 0), parent.get("z", 0))
                child_pos = (child.get("x", 0), child.get("y", 0), child.get("z", 0))

                rotation = self.calculate_bone_rotation(parent_pos, child_pos)
                transforms[bone_name] = {
                    "rotation": list(rotation),
                    "position": list(parent_pos),
                }

        # Head - usa nose landmark per direzione
        if len(landmarks) > 0:
            nose = landmarks[0]
            transforms["Head"] = {
                "rotation": [0.0, 0.0, 0.0, 1.0],
                "position": [nose.get("x", 0), nose.get("y", 0), nose.get("z", 0)],
            }

        # Hips - punto medio tra le anche
        if len(landmarks) > 24:
            left_hip = landmarks[23]
            right_hip = landmarks[24]
            hip_x = (left_hip.get("x", 0) + right_hip.get("x", 0)) / 2
            hip_y = (left_hip.get("y", 0) + right_hip.get("y", 0)) / 2
            hip_z = (left_hip.get("z", 0) + right_hip.get("z", 0)) / 2
            transforms["Hips"] = {
                "rotation": [0.0, 0.0, 0.0, 1.0],
                "position": [hip_x, hip_y, hip_z],
            }

        # Shoulders
        for idx, bone_name in [(11, "LeftShoulder"), (12, "RightShoulder")]:
            if idx < len(landmarks):
                lm = landmarks[idx]
                transforms[bone_name] = {
                    "rotation": [0.0, 0.0, 0.0, 1.0],
                    "position": [lm.get("x", 0), lm.get("y", 0), lm.get("z", 0)],
                }

        return transforms

    def _process_hand_landmarks(
        self, landmarks: List[dict], side: str
    ) -> Dict[str, dict]:
        """Calcola transforms per i bones delle dita"""
        mapping = self.LEFT_HAND_MAPPING if side == "left" else self.RIGHT_HAND_MAPPING
        transforms = {}

        # Coppie finger bone per calcolo rotazione
        finger_pairs = [
            (0, 1), (1, 2), (2, 3), (3, 4),     # thumb
            (0, 5), (5, 6), (6, 7), (7, 8),     # index
            (0, 9), (9, 10), (10, 11), (11, 12), # middle
            (0, 13), (13, 14), (14, 15), (15, 16), # ring
            (0, 17), (17, 18), (18, 19), (19, 20), # pinky
        ]

        for parent_idx, child_idx in finger_pairs:
            if child_idx in mapping and parent_idx < len(landmarks) and child_idx < len(landmarks):
                parent = landmarks[parent_idx]
                child = landmarks[child_idx]

                parent_pos = (parent.get("x", 0), parent.get("y", 0), parent.get("z", 0))
                child_pos = (child.get("x", 0), child.get("y", 0), child.get("z", 0))

                bone_name = mapping[child_idx]
                rotation = self.calculate_bone_rotation(parent_pos, child_pos)
                transforms[bone_name] = {
                    "rotation": list(rotation),
                    "position": list(parent_pos),
                }

        # Wrist bone
        if 0 in mapping and len(landmarks) > 0:
            wrist = landmarks[0]
            wrist_name = mapping[0]
            transforms[wrist_name] = {
                "rotation": [0.0, 0.0, 0.0, 1.0],
                "position": [wrist.get("x", 0), wrist.get("y", 0), wrist.get("z", 0)],
            }

        return transforms

    @staticmethod
    def calculate_bone_rotation(
        parent_pos: Tuple[float, float, float],
        child_pos: Tuple[float, float, float],
        reference_up: Tuple[float, float, float] = (0.0, 1.0, 0.0),
    ) -> Tuple[float, float, float, float]:
        """
        Calcola quaternion rotation per un bone dati 2 punti (parent -> child).

        WHY questo algoritmo:
        1. Calcola il vettore direzione parent->child
        2. Trova la rotazione che porta il vettore "up" di riferimento
           nella direzione calcolata
        3. Usa il prodotto vettoriale per trovare l'asse di rotazione
        4. Costruisce il quaternione dall'asse-angolo

        Returns: (x, y, z, w) quaternion
        """
        # Vettore direzione
        dx = child_pos[0] - parent_pos[0]
        dy = child_pos[1] - parent_pos[1]
        dz = child_pos[2] - parent_pos[2]

        # Normalizza
        length = math.sqrt(dx * dx + dy * dy + dz * dz)
        if length < 1e-6:
            return (0.0, 0.0, 0.0, 1.0)  # Identity quaternion

        dx /= length
        dy /= length
        dz /= length

        # Prodotto vettoriale con vettore di riferimento per trovare asse rotazione
        ux, uy, uz = reference_up
        axis_x = uy * dz - uz * dy
        axis_y = uz * dx - ux * dz
        axis_z = ux * dy - uy * dx

        axis_length = math.sqrt(axis_x * axis_x + axis_y * axis_y + axis_z * axis_z)

        if axis_length < 1e-6:
            # Vettori paralleli o anti-paralleli
            dot = ux * dx + uy * dy + uz * dz
            if dot > 0:
                return (0.0, 0.0, 0.0, 1.0)
            else:
                return (1.0, 0.0, 0.0, 0.0)

        # Normalizza asse
        axis_x /= axis_length
        axis_y /= axis_length
        axis_z /= axis_length

        # Angolo tra i vettori
        dot = ux * dx + uy * dy + uz * dz
        dot = max(-1.0, min(1.0, dot))  # Clamp per sicurezza numerica
        angle = math.acos(dot)

        # Quaternione da asse-angolo
        half_angle = angle / 2.0
        sin_half = math.sin(half_angle)
        cos_half = math.cos(half_angle)

        return (
            axis_x * sin_half,
            axis_y * sin_half,
            axis_z * sin_half,
            cos_half,
        )

    def get_available_styles(self) -> List[dict]:
        """Ritorna la lista degli stili marziali disponibili"""
        return [
            {
                "value": "karate",
                "label": "Karate",
                "description": "Avatar ottimizzati per kata e kumite",
            },
            {
                "value": "kung_fu",
                "label": "Kung Fu",
                "description": "Avatar per forme e tecniche di kung fu",
            },
            {
                "value": "taekwondo",
                "label": "Taekwondo",
                "description": "Avatar per poomsae e calci alti",
            },
            {
                "value": "judo",
                "label": "Judo",
                "description": "Avatar per proiezioni e tecniche a terra",
            },
            {
                "value": "generic",
                "label": "Generico",
                "description": "Avatar generico adatto a tutti gli stili",
            },
        ]

    def get_model_path(self, filename: str) -> Path:
        """Ritorna il path completo per un file modello avatar"""
        return AVATAR_STORAGE_PATH / "models" / filename

    def get_thumbnail_path(self, filename: str) -> Path:
        """Ritorna il path completo per una thumbnail avatar"""
        return AVATAR_STORAGE_PATH / "thumbnails" / filename

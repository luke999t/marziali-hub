"""
🎓 AI_MODULE: Blender Export Service
🎓 AI_DESCRIPTION: Prepara skeleton JSON per import in Blender con retarget Mixamo
🎓 AI_BUSINESS: Bridge tra sistema web e Blender per avatar 360°
🎓 AI_TEACHING: Formato BVH/JSON compatibile con Mixamo retarget, bone mapping

🔄 ALTERNATIVE_VALUTATE:
- BVH diretto: Scartato, meno flessibile per modifiche
- FBX: Scartato, richiede SDK proprietario
- JSON custom: Scelto, massima flessibilità e debugging

💡 PERCHÉ_QUESTA_SOLUZIONE:
- JSON leggibile e debuggabile
- Script Python per Blender incluso
- Mapping completo 75 landmarks → Mixamo rig
- Supporto per quality scoring e gap filling

📊 METRICHE_SUCCESSO:
- Tempo export: < 5s per 1000 frames
- Accuratezza retarget: > 95%
- File size: < 10MB per 60s di animazione
"""

import json
import logging
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple
from datetime import datetime
from dataclasses import dataclass, asdict
import math

logger = logging.getLogger(__name__)

# ============================================================================
# MIXAMO RIG MAPPING
# ============================================================================

# MediaPipe 75 landmarks → Mixamo bone names
MIXAMO_BONE_MAPPING = {
    # Body (33 landmarks)
    0: "Head",
    1: "Head",  # Left eye inner
    2: "Head",  # Left eye
    3: "Head",  # Left eye outer
    4: "Head",  # Right eye inner
    5: "Head",  # Right eye
    6: "Head",  # Right eye outer
    7: "Head",  # Left ear
    8: "Head",  # Right ear
    9: "Head",  # Mouth left
    10: "Head",  # Mouth right
    11: "LeftShoulder",
    12: "RightShoulder",
    13: "LeftArm",
    14: "RightArm",
    15: "LeftForeArm",
    16: "RightForeArm",
    17: "LeftHand",
    18: "RightHand",
    19: "LeftHand",  # Left pinky
    20: "RightHand",  # Right pinky
    21: "LeftHand",  # Left index
    22: "RightHand",  # Right index
    23: "LeftUpLeg",
    24: "RightUpLeg",
    25: "LeftLeg",
    26: "RightLeg",
    27: "LeftFoot",
    28: "RightFoot",
    29: "LeftFoot",  # Left heel
    30: "RightFoot",  # Right heel
    31: "LeftToeBase",
    32: "RightToeBase",
}

# Hand landmarks (21 per hand) → Mixamo finger bones
HAND_BONE_MAPPING = {
    # Left hand (offset 0)
    0: "LeftHand",
    1: "LeftHandThumb1", 2: "LeftHandThumb2", 3: "LeftHandThumb3", 4: "LeftHandThumb4",
    5: "LeftHandIndex1", 6: "LeftHandIndex2", 7: "LeftHandIndex3", 8: "LeftHandIndex4",
    9: "LeftHandMiddle1", 10: "LeftHandMiddle2", 11: "LeftHandMiddle3", 12: "LeftHandMiddle4",
    13: "LeftHandRing1", 14: "LeftHandRing2", 15: "LeftHandRing3", 16: "LeftHandRing4",
    17: "LeftHandPinky1", 18: "LeftHandPinky2", 19: "LeftHandPinky3", 20: "LeftHandPinky4",
    # Right hand (offset 21)
    21: "RightHand",
    22: "RightHandThumb1", 23: "RightHandThumb2", 24: "RightHandThumb3", 25: "RightHandThumb4",
    26: "RightHandIndex1", 27: "RightHandIndex2", 28: "RightHandIndex3", 29: "RightHandIndex4",
    30: "RightHandMiddle1", 31: "RightHandMiddle2", 32: "RightHandMiddle3", 33: "RightHandMiddle4",
    34: "RightHandRing1", 35: "RightHandRing2", 36: "RightHandRing3", 37: "RightHandRing4",
    38: "RightHandPinky1", 39: "RightHandPinky2", 40: "RightHandPinky3", 41: "RightHandPinky4",
}


@dataclass
class BlenderFrame:
    """Single frame for Blender import"""
    frame_index: int
    timestamp: float
    bones: Dict[str, Dict[str, float]]  # bone_name -> {x, y, z, rx, ry, rz}
    quality_score: float
    has_gap: bool = False


@dataclass
class BlenderExportPackage:
    """Complete export package for Blender"""
    version: str = "1.0"
    export_date: str = ""
    source_asset_id: str = ""
    total_frames: int = 0
    fps: float = 30.0
    duration: float = 0.0
    frames: List[Dict] = None
    metadata: Dict = None
    import_script_path: str = ""

    def __post_init__(self):
        if self.frames is None:
            self.frames = []
        if self.metadata is None:
            self.metadata = {}


class BlenderExportService:
    """
    Converte skeleton JSON interno → formato Blender-ready

    Output:
    - skeleton_blender.json (75 landmarks mappati a Mixamo rig)
    - metadata.json (fps, duration, quality scores)
    - import_script.py (script Python per Blender)
    """

    def __init__(self, output_dir: str = "data/blender_exports"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def export_for_blender(
        self,
        skeleton_data: Dict[str, Any],
        asset_id: str,
        project_name: str = "Untitled"
    ) -> Dict[str, Any]:
        """
        Main export function: converts internal skeleton → Blender format

        Args:
            skeleton_data: Internal skeleton JSON with frames and landmarks
            asset_id: Unique identifier for this skeleton
            project_name: Human-readable project name

        Returns:
            {
                "success": True,
                "export_path": "/path/to/export/",
                "files": {
                    "skeleton": "skeleton_blender.json",
                    "metadata": "metadata.json",
                    "script": "import_blender.py"
                },
                "stats": {
                    "total_frames": 1000,
                    "duration": 33.3,
                    "quality_score": 0.92
                }
            }
        """
        try:
            export_id = f"{asset_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            export_path = self.output_dir / export_id
            export_path.mkdir(parents=True, exist_ok=True)

            # Extract frames
            frames = skeleton_data.get("frames", [])
            if not frames:
                raise ValueError("No frames in skeleton data")

            # Get metadata
            video_meta = skeleton_data.get("video_metadata", {})
            fps = video_meta.get("fps", 30.0)

            # Convert frames to Blender format
            blender_frames = []
            total_quality = 0.0
            gap_count = 0

            for frame in frames:
                blender_frame = self._convert_frame(frame)
                blender_frames.append(asdict(blender_frame))
                total_quality += blender_frame.quality_score
                if blender_frame.has_gap:
                    gap_count += 1

            avg_quality = total_quality / len(blender_frames) if blender_frames else 0
            duration = len(blender_frames) / fps if fps > 0 else 0

            # Create export package
            package = BlenderExportPackage(
                version="1.0",
                export_date=datetime.now().isoformat(),
                source_asset_id=asset_id,
                total_frames=len(blender_frames),
                fps=fps,
                duration=duration,
                frames=blender_frames,
                metadata={
                    "project_name": project_name,
                    "avg_quality_score": avg_quality,
                    "gap_frames": gap_count,
                    "source_resolution": video_meta.get("resolution", {}),
                    "bone_mapping": "mixamo_standard",
                }
            )

            # Save skeleton JSON
            skeleton_path = export_path / "skeleton_blender.json"
            with open(skeleton_path, "w") as f:
                json.dump(asdict(package), f, indent=2)

            # Save metadata
            metadata_path = export_path / "metadata.json"
            with open(metadata_path, "w") as f:
                json.dump({
                    "export_id": export_id,
                    "asset_id": asset_id,
                    "project_name": project_name,
                    "total_frames": len(blender_frames),
                    "fps": fps,
                    "duration": duration,
                    "avg_quality": avg_quality,
                    "gaps": gap_count,
                    "export_date": package.export_date,
                }, f, indent=2)

            # Generate Blender import script
            script_path = export_path / "import_blender.py"
            self._generate_blender_script(script_path, export_id)

            logger.info(f"Blender export completed: {export_path}")

            return {
                "success": True,
                "export_id": export_id,
                "export_path": str(export_path),
                "files": {
                    "skeleton": str(skeleton_path),
                    "metadata": str(metadata_path),
                    "script": str(script_path),
                },
                "stats": {
                    "total_frames": len(blender_frames),
                    "duration": duration,
                    "fps": fps,
                    "quality_score": avg_quality,
                    "gaps": gap_count,
                }
            }

        except Exception as e:
            logger.error(f"Blender export failed: {e}")
            return {
                "success": False,
                "error": str(e),
            }

    def _convert_frame(self, frame: Dict) -> BlenderFrame:
        """Convert internal frame format to Blender format"""
        landmarks = frame.get("pose_landmarks", [])
        frame_index = frame.get("frame_index", 0)
        timestamp = frame.get("timestamp", 0.0)
        confidence = frame.get("confidence", 0.5)

        bones = {}
        has_gap = False

        # Map landmarks to Mixamo bones
        for idx, landmark in enumerate(landmarks):
            if idx >= 33:  # Only body landmarks for now
                break

            bone_name = MIXAMO_BONE_MAPPING.get(idx, f"Landmark_{idx}")

            # Check for missing/low confidence
            visibility = landmark.get("visibility", 0)
            if visibility < 0.3:
                has_gap = True

            # Convert coordinates (MediaPipe uses normalized 0-1, Blender uses meters)
            bones[bone_name] = {
                "x": landmark.get("x", 0.5) * 2 - 1,  # -1 to 1
                "y": landmark.get("y", 0.5) * 2 - 1,
                "z": landmark.get("z", 0) * 2,  # Depth
                "visibility": visibility,
            }

        # Add hand landmarks if present
        left_hand = frame.get("left_hand_landmarks", [])
        right_hand = frame.get("right_hand_landmarks", [])

        for idx, landmark in enumerate(left_hand[:21]):
            bone_name = HAND_BONE_MAPPING.get(idx, f"LeftHand_{idx}")
            bones[bone_name] = {
                "x": landmark.get("x", 0.5) * 2 - 1,
                "y": landmark.get("y", 0.5) * 2 - 1,
                "z": landmark.get("z", 0) * 2,
                "visibility": landmark.get("visibility", 0),
            }

        for idx, landmark in enumerate(right_hand[:21]):
            bone_name = HAND_BONE_MAPPING.get(idx + 21, f"RightHand_{idx}")
            bones[bone_name] = {
                "x": landmark.get("x", 0.5) * 2 - 1,
                "y": landmark.get("y", 0.5) * 2 - 1,
                "z": landmark.get("z", 0) * 2,
                "visibility": landmark.get("visibility", 0),
            }

        return BlenderFrame(
            frame_index=frame_index,
            timestamp=timestamp,
            bones=bones,
            quality_score=confidence,
            has_gap=has_gap,
        )

    def _generate_blender_script(self, output_path: Path, export_id: str):
        """Generate Python script for Blender import"""
        script_content = f'''"""
Blender Import Script for Skeleton Animation
Export ID: {export_id}
Generated: {datetime.now().isoformat()}

Usage:
1. Open Blender
2. File > Import > Run Script (or paste in Scripting tab)
3. Run this script
4. Import your Mixamo character
5. Run retarget_to_mixamo()
"""

import bpy
import json
import os
from mathutils import Vector, Euler

# Configuration
SKELETON_FILE = "skeleton_blender.json"
SCRIPT_DIR = os.path.dirname(os.path.realpath(__file__))

def load_skeleton_data():
    """Load skeleton JSON data"""
    json_path = os.path.join(SCRIPT_DIR, SKELETON_FILE)
    with open(json_path, 'r') as f:
        return json.load(f)

def create_armature(data):
    """Create armature from skeleton data"""
    # Create armature
    bpy.ops.object.armature_add(enter_editmode=True)
    armature = bpy.context.object
    armature.name = "SkeletonArmature"

    # Get edit bones
    edit_bones = armature.data.edit_bones

    # Remove default bone
    for bone in edit_bones:
        edit_bones.remove(bone)

    # Create bones from first frame
    if data['frames']:
        first_frame = data['frames'][0]
        for bone_name, bone_data in first_frame['bones'].items():
            bone = edit_bones.new(bone_name)
            bone.head = Vector((bone_data['x'], bone_data['z'], -bone_data['y']))
            bone.tail = bone.head + Vector((0, 0.1, 0))

    bpy.ops.object.mode_set(mode='OBJECT')
    return armature

def animate_armature(armature, data):
    """Apply animation keyframes"""
    fps = data.get('fps', 30)
    bpy.context.scene.render.fps = int(fps)
    bpy.context.scene.frame_end = data['total_frames']

    for frame_data in data['frames']:
        frame_idx = frame_data['frame_index']
        bpy.context.scene.frame_set(frame_idx)

        for bone_name, bone_pos in frame_data['bones'].items():
            if bone_name in armature.pose.bones:
                pose_bone = armature.pose.bones[bone_name]
                pose_bone.location = Vector((
                    bone_pos['x'],
                    bone_pos['z'],
                    -bone_pos['y']
                ))
                pose_bone.keyframe_insert(data_path="location", frame=frame_idx)

def retarget_to_mixamo(source_armature, target_armature_name="Armature"):
    """Retarget animation to Mixamo character"""
    # This is a simplified retarget - full implementation would use
    # bone constraints or animation retargeting addon
    target = bpy.data.objects.get(target_armature_name)
    if not target:
        print(f"Target armature '{{target_armature_name}}' not found")
        return

    # Copy animation data
    if source_armature.animation_data:
        target.animation_data_create()
        target.animation_data.action = source_armature.animation_data.action.copy()

    print("Retarget completed")

def render_360(output_path, frames=8):
    """Render avatar from multiple angles"""
    angles = [i * (360 / frames) for i in range(frames)]

    # Create camera if not exists
    if "Camera_360" not in bpy.data.objects:
        bpy.ops.object.camera_add()
        camera = bpy.context.object
        camera.name = "Camera_360"
    else:
        camera = bpy.data.objects["Camera_360"]

    # Setup camera orbit
    camera.location = (0, -3, 1.5)

    for i, angle in enumerate(angles):
        # Rotate camera around Z axis
        import math
        rad = math.radians(angle)
        camera.location.x = 3 * math.sin(rad)
        camera.location.y = -3 * math.cos(rad)

        # Point at origin
        direction = Vector((0, 0, 1)) - camera.location
        camera.rotation_euler = direction.to_track_quat('-Z', 'Y').to_euler()

        # Render
        bpy.context.scene.render.filepath = os.path.join(output_path, f"render_{{i:03d}}.png")
        bpy.ops.render.render(write_still=True)

    print(f"Rendered {{frames}} angles to {{output_path}}")

# Main execution
if __name__ == "__main__":
    print("Loading skeleton data...")
    data = load_skeleton_data()

    print(f"Creating armature with {{data['total_frames']}} frames...")
    armature = create_armature(data)

    print("Applying animation...")
    animate_armature(armature, data)

    print("Done! Use retarget_to_mixamo() to apply to your character")
'''

        with open(output_path, "w") as f:
            f.write(script_content)

        logger.info(f"Generated Blender import script: {output_path}")

    def fill_gaps(
        self,
        frames: List[Dict],
        max_gap_frames: int = 10
    ) -> List[Dict]:
        """
        Fill gaps in skeleton data using interpolation

        Args:
            frames: List of frame dicts
            max_gap_frames: Maximum gap to fill (larger gaps kept as-is)

        Returns:
            Frames with gaps filled via linear interpolation
        """
        if len(frames) < 2:
            return frames

        filled_frames = []

        for i, frame in enumerate(frames):
            if not frame.get("has_gap", False):
                filled_frames.append(frame)
                continue

            # Find previous and next valid frames
            prev_frame = None
            next_frame = None

            for j in range(i - 1, max(0, i - max_gap_frames) - 1, -1):
                if not frames[j].get("has_gap", False):
                    prev_frame = frames[j]
                    break

            for j in range(i + 1, min(len(frames), i + max_gap_frames + 1)):
                if not frames[j].get("has_gap", False):
                    next_frame = frames[j]
                    break

            if prev_frame and next_frame:
                # Interpolate
                filled_frame = self._interpolate_frame(
                    prev_frame, next_frame, frame["frame_index"]
                )
                filled_frame["interpolated"] = True
                filled_frames.append(filled_frame)
            else:
                # Can't fill, keep original
                filled_frames.append(frame)

        return filled_frames

    def _interpolate_frame(
        self,
        frame_a: Dict,
        frame_b: Dict,
        target_index: int
    ) -> Dict:
        """Linear interpolation between two frames"""
        idx_a = frame_a["frame_index"]
        idx_b = frame_b["frame_index"]

        if idx_b == idx_a:
            return frame_a.copy()

        t = (target_index - idx_a) / (idx_b - idx_a)

        bones_a = frame_a.get("bones", {})
        bones_b = frame_b.get("bones", {})

        interpolated_bones = {}
        for bone_name in set(bones_a.keys()) | set(bones_b.keys()):
            a = bones_a.get(bone_name, {"x": 0, "y": 0, "z": 0, "visibility": 0})
            b = bones_b.get(bone_name, {"x": 0, "y": 0, "z": 0, "visibility": 0})

            interpolated_bones[bone_name] = {
                "x": a["x"] + t * (b["x"] - a["x"]),
                "y": a["y"] + t * (b["y"] - a["y"]),
                "z": a["z"] + t * (b["z"] - a["z"]),
                "visibility": a["visibility"] + t * (b["visibility"] - a["visibility"]),
            }

        return {
            "frame_index": target_index,
            "timestamp": frame_a["timestamp"] + t * (frame_b["timestamp"] - frame_a["timestamp"]),
            "bones": interpolated_bones,
            "quality_score": (frame_a["quality_score"] + frame_b["quality_score"]) / 2,
            "has_gap": False,
        }

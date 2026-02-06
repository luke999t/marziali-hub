from pathlib import Path
import json
import numpy as np
from typing import Dict, List, Tuple, Optional
from dataclasses import dataclass
import cv2

@dataclass
class ComparisonMetrics:
    frame_similarity: float
    position_error: float
    velocity_difference: float
    synchronization_score: float
    overall_similarity: float

class SkeletonComparator:
    def __init__(self):
        self.joint_weights = self._get_joint_weights()

    def _get_joint_weights(self) -> Dict[int, float]:
        weights = {}
        for i in range(33):
            if i in [11, 12, 13, 14, 23, 24, 25, 26]:
                weights[i] = 2.0
            elif i in [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10]:
                weights[i] = 1.5
            else:
                weights[i] = 1.0
        return weights

    def load_skeleton_data(self, json_path: str) -> Dict:
        with open(json_path, 'r') as f:
            return json.load(f)

    def calculate_position_error(self, frame1: Dict, frame2: Dict) -> float:
        if not frame1.get('body') or not frame2.get('body'):
            return 1.0

        total_error = 0.0
        total_weight = 0.0

        for lm1, lm2 in zip(frame1['body'], frame2['body']):
            weight = self.joint_weights.get(lm1['id'], 1.0)
            dx = lm1['x'] - lm2['x']
            dy = lm1['y'] - lm2['y']
            dz = lm1['z'] - lm2['z']
            error = np.sqrt(dx*dx + dy*dy + dz*dz)
            total_error += error * weight
            total_weight += weight

        return total_error / total_weight if total_weight > 0 else 1.0

    def calculate_velocity(self, frames: List[Dict], fps: float) -> List[np.ndarray]:
        velocities = []
        dt = 1.0 / fps

        for i in range(len(frames) - 1):
            if not frames[i].get('body') or not frames[i+1].get('body'):
                velocities.append(np.zeros(33 * 3))
                continue

            vel = []
            for lm1, lm2 in zip(frames[i]['body'], frames[i+1]['body']):
                vx = (lm2['x'] - lm1['x']) / dt
                vy = (lm2['y'] - lm1['y']) / dt
                vz = (lm2['z'] - lm1['z']) / dt
                vel.extend([vx, vy, vz])
            velocities.append(np.array(vel))

        if velocities:
            velocities.append(velocities[-1])
        return velocities

    def compare_frames(self, data1: Dict, data2: Dict, frame_idx: int) -> ComparisonMetrics:
        frames1 = data1['frames']
        frames2 = data2['frames']

        if frame_idx >= len(frames1) or frame_idx >= len(frames2):
            return ComparisonMetrics(0.0, 1.0, 1.0, 0.0, 0.0)

        frame1 = frames1[frame_idx]
        frame2 = frames2[frame_idx]

        position_error = self.calculate_position_error(frame1, frame2)
        frame_similarity = max(0, 1.0 - position_error)

        vel1 = self.calculate_velocity(frames1, data1['video_metadata']['fps'])
        vel2 = self.calculate_velocity(frames2, data2['video_metadata']['fps'])

        velocity_diff = 0.0
        if frame_idx < len(vel1) and frame_idx < len(vel2):
            velocity_diff = np.linalg.norm(vel1[frame_idx] - vel2[frame_idx])

        sync_score = 1.0 - min(1.0, velocity_diff / 10.0)
        overall = (frame_similarity * 0.6 + sync_score * 0.4)

        return ComparisonMetrics(
            frame_similarity=frame_similarity,
            position_error=position_error,
            velocity_difference=velocity_diff,
            synchronization_score=sync_score,
            overall_similarity=overall
        )

    def compare_sequences(self, data1: Dict, data2: Dict) -> Dict:
        frames1 = data1['frames']
        frames2 = data2['frames']
        min_frames = min(len(frames1), len(frames2))

        metrics_per_frame = []
        for i in range(min_frames):
            metrics = self.compare_frames(data1, data2, i)
            metrics_per_frame.append(metrics)

        avg_similarity = np.mean([m.overall_similarity for m in metrics_per_frame])
        avg_position_error = np.mean([m.position_error for m in metrics_per_frame])
        avg_sync = np.mean([m.synchronization_score for m in metrics_per_frame])

        return {
            'total_frames_compared': min_frames,
            'average_similarity': float(avg_similarity),
            'average_position_error': float(avg_position_error),
            'average_synchronization': float(avg_sync),
            'frame_by_frame_metrics': [
                {
                    'frame': i,
                    'similarity': m.overall_similarity,
                    'position_error': m.position_error,
                    'sync_score': m.synchronization_score
                }
                for i, m in enumerate(metrics_per_frame)
            ]
        }

class VideoComparator:
    def __init__(self):
        self.skeleton_comparator = SkeletonComparator()

    def create_side_by_side_video(
        self,
        video1_path: str,
        video2_path: str,
        skeleton1_path: str,
        skeleton2_path: str,
        output_path: str,
        show_skeleton: bool = True
    ):
        cap1 = cv2.VideoCapture(video1_path)
        cap2 = cv2.VideoCapture(video2_path)

        width1 = int(cap1.get(cv2.CAP_PROP_FRAME_WIDTH))
        height1 = int(cap1.get(cv2.CAP_PROP_FRAME_HEIGHT))
        width2 = int(cap2.get(cv2.CAP_PROP_FRAME_WIDTH))
        height2 = int(cap2.get(cv2.CAP_PROP_FRAME_HEIGHT))
        fps1 = cap1.get(cv2.CAP_PROP_FPS)
        fps2 = cap2.get(cv2.CAP_PROP_FPS)
        fps = min(fps1, fps2)

        target_height = max(height1, height2)
        scale1 = target_height / height1
        scale2 = target_height / height2
        new_width1 = int(width1 * scale1)
        new_width2 = int(width2 * scale2)

        output_width = new_width1 + new_width2 + 60
        output_height = target_height + 100

        fourcc = cv2.VideoWriter_fourcc(*'mp4v')
        out = cv2.VideoWriter(output_path, fourcc, fps, (output_width, output_height))

        data1 = self.skeleton_comparator.load_skeleton_data(skeleton1_path) if show_skeleton else None
        data2 = self.skeleton_comparator.load_skeleton_data(skeleton2_path) if show_skeleton else None

        frame_idx = 0

        while True:
            ret1, frame1 = cap1.read()
            ret2, frame2 = cap2.read()

            if not ret1 or not ret2:
                break

            frame1_resized = cv2.resize(frame1, (new_width1, target_height))
            frame2_resized = cv2.resize(frame2, (new_width2, target_height))

            if show_skeleton and data1 and data2:
                frame1_resized = self._draw_skeleton(frame1_resized, data1['frames'][frame_idx] if frame_idx < len(data1['frames']) else None)
                frame2_resized = self._draw_skeleton(frame2_resized, data2['frames'][frame_idx] if frame_idx < len(data2['frames']) else None)

            combined = np.zeros((output_height, output_width, 3), dtype=np.uint8)
            combined[50:50+target_height, 20:20+new_width1] = frame1_resized
            combined[50:50+target_height, 40+new_width1:40+new_width1+new_width2] = frame2_resized

            if show_skeleton and data1 and data2 and frame_idx < min(len(data1['frames']), len(data2['frames'])):
                metrics = self.skeleton_comparator.compare_frames(data1, data2, frame_idx)
                cv2.putText(combined, f"Similarity: {metrics.overall_similarity:.1%}", (20, 30),
                           cv2.FONT_HERSHEY_SIMPLEX, 0.7, (0, 255, 0), 2)
                cv2.putText(combined, f"Position Error: {metrics.position_error:.3f}", (300, 30),
                           cv2.FONT_HERSHEY_SIMPLEX, 0.7, (0, 255, 255), 2)
                cv2.putText(combined, f"Sync: {metrics.synchronization_score:.1%}", (600, 30),
                           cv2.FONT_HERSHEY_SIMPLEX, 0.7, (255, 255, 0), 2)

            cv2.putText(combined, f"Frame: {frame_idx}", (output_width - 150, 30),
                       cv2.FONT_HERSHEY_SIMPLEX, 0.6, (255, 255, 255), 2)

            out.write(combined)
            frame_idx += 1

        cap1.release()
        cap2.release()
        out.release()

    def _draw_skeleton(self, frame: np.ndarray, skeleton_frame: Optional[Dict]) -> np.ndarray:
        if not skeleton_frame or not skeleton_frame.get('body'):
            return frame

        h, w = frame.shape[:2]
        for lm in skeleton_frame['body']:
            x = int(lm['x'] * w)
            y = int(lm['y'] * h)
            cv2.circle(frame, (x, y), 3, (0, 255, 0), -1)

        return frame

def main():
    comparator = SkeletonComparator()
    video_comparator = VideoComparator()

    skeleton1 = r"C:\Users\utente\Desktop\cursor\Progetto_media_center\MediaCenter_Modular\modules\video_studio\src\test_skeleton.json"
    skeleton2 = r"C:\Users\utente\Desktop\cursor\Progetto_media_center\MediaCenter_Modular\modules\video_studio\src\test_skeleton.json"

    if not Path(skeleton1).exists() or not Path(skeleton2).exists():
        print("Skeleton files not found")
        return

    data1 = comparator.load_skeleton_data(skeleton1)
    data2 = comparator.load_skeleton_data(skeleton2)

    results = comparator.compare_sequences(data1, data2)

    print(f"Comparison Results:")
    print(f"  Frames compared: {results['total_frames_compared']}")
    print(f"  Average similarity: {results['average_similarity']:.1%}")
    print(f"  Average position error: {results['average_position_error']:.3f}")
    print(f"  Average synchronization: {results['average_synchronization']:.1%}")

if __name__ == '__main__':
    main()

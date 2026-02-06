"""
Advanced Analytics Module
Generates heat maps, motion trails, and advanced visualizations for skeleton data
"""

import numpy as np
from typing import List, Dict, Tuple, Optional
import json
from dataclasses import dataclass


@dataclass
class MotionPoint:
    """Single point in motion trail"""
    x: float
    y: float
    timestamp: float
    velocity: float = 0.0


class AdvancedAnalytics:
    """Advanced analytics for skeleton data"""

    def generate_heat_map(self, skeleton_data: Dict, width: int = 640, height: int = 480, joint_name: str = "nose") -> np.ndarray:
        """
        Generate heat map showing joint position density

        Args:
            skeleton_data: Skeleton data with frames
            width: Output width
            height: Output height
            joint_name: Joint to track (e.g., 'nose', 'left_hand', 'right_hand')

        Returns:
            2D numpy array representing heat map
        """
        heat_map = np.zeros((height, width), dtype=np.float32)

        frames = skeleton_data.get('frames', [])
        for frame in frames:
            landmarks = frame.get('landmarks', {})
            if joint_name in landmarks:
                joint = landmarks[joint_name]
                x = int(joint['x'] * width)
                y = int(joint['y'] * height)

                if 0 <= x < width and 0 <= y < height:
                    # Gaussian blur around the point
                    for dy in range(-10, 11):
                        for dx in range(-10, 11):
                            nx, ny = x + dx, y + dy
                            if 0 <= nx < width and 0 <= ny < height:
                                distance = np.sqrt(dx**2 + dy**2)
                                heat_map[ny, nx] += np.exp(-distance**2 / 50)

        # Normalize
        if heat_map.max() > 0:
            heat_map = (heat_map / heat_map.max() * 255).astype(np.uint8)

        return heat_map

    def generate_motion_trail(self, skeleton_data: Dict, joint_name: str = "nose", max_points: int = 100) -> List[MotionPoint]:
        """
        Generate motion trail for a specific joint

        Args:
            skeleton_data: Skeleton data with frames
            joint_name: Joint to track
            max_points: Maximum trail points

        Returns:
            List of MotionPoint objects
        """
        trail = []
        frames = skeleton_data.get('frames', [])

        prev_point = None
        for i, frame in enumerate(frames):
            landmarks = frame.get('landmarks', {})
            if joint_name in landmarks:
                joint = landmarks[joint_name]
                timestamp = frame.get('timestamp', i / 30.0)  # Assume 30 FPS

                current_point = MotionPoint(
                    x=joint['x'],
                    y=joint['y'],
                    timestamp=timestamp
                )

                # Calculate velocity
                if prev_point:
                    dx = current_point.x - prev_point.x
                    dy = current_point.y - prev_point.y
                    dt = current_point.timestamp - prev_point.timestamp
                    if dt > 0:
                        current_point.velocity = np.sqrt(dx**2 + dy**2) / dt

                trail.append(current_point)
                prev_point = current_point

                # Limit trail length
                if len(trail) > max_points:
                    trail.pop(0)

        return trail

    def calculate_joint_velocity_profile(self, skeleton_data: Dict, joint_name: str = "right_hand") -> List[Dict]:
        """
        Calculate velocity profile over time for a joint

        Returns:
            List of dicts with timestamp, velocity, acceleration
        """
        profile = []
        trail = self.generate_motion_trail(skeleton_data, joint_name, max_points=10000)

        prev_velocity = 0
        for i, point in enumerate(trail):
            acceleration = 0
            if i > 0:
                dt = point.timestamp - trail[i-1].timestamp
                if dt > 0:
                    acceleration = (point.velocity - prev_velocity) / dt

            profile.append({
                "timestamp": point.timestamp,
                "velocity": point.velocity,
                "acceleration": acceleration
            })

            prev_velocity = point.velocity

        return profile

    def detect_power_moments(self, skeleton_data: Dict, velocity_threshold: float = 2.0) -> List[Dict]:
        """
        Detect high-power movements (strikes, kicks, etc.)

        Args:
            skeleton_data: Skeleton data
            velocity_threshold: Minimum velocity to consider as power moment

        Returns:
            List of power moments with timestamp, joint, velocity
        """
        power_moments = []
        joints_to_track = ["right_hand", "left_hand", "right_foot", "left_foot"]

        for joint in joints_to_track:
            profile = self.calculate_joint_velocity_profile(skeleton_data, joint)

            for i, point in enumerate(profile):
                if point['velocity'] > velocity_threshold:
                    power_moments.append({
                        "timestamp": point['timestamp'],
                        "joint": joint,
                        "velocity": point['velocity'],
                        "acceleration": point['acceleration'],
                        "frame": i
                    })

        # Sort by timestamp
        power_moments.sort(key=lambda x: x['timestamp'])
        return power_moments

    def analyze_range_of_motion(self, skeleton_data: Dict) -> Dict:
        """
        Analyze range of motion for key joints

        Returns:
            Dict with min/max positions and range for each joint
        """
        rom_analysis = {}
        frames = skeleton_data.get('frames', [])

        # Collect all positions
        joint_positions = {}
        for frame in frames:
            landmarks = frame.get('landmarks', {})
            for joint_name, joint_data in landmarks.items():
                if joint_name not in joint_positions:
                    joint_positions[joint_name] = {'x': [], 'y': [], 'z': []}

                joint_positions[joint_name]['x'].append(joint_data.get('x', 0))
                joint_positions[joint_name]['y'].append(joint_data.get('y', 0))
                joint_positions[joint_name]['z'].append(joint_data.get('z', 0))

        # Calculate range for each joint
        for joint_name, positions in joint_positions.items():
            rom_analysis[joint_name] = {
                "x_range": max(positions['x']) - min(positions['x']),
                "y_range": max(positions['y']) - min(positions['y']),
                "z_range": max(positions['z']) - min(positions['z']),
                "total_range": np.sqrt(
                    (max(positions['x']) - min(positions['x']))**2 +
                    (max(positions['y']) - min(positions['y']))**2 +
                    (max(positions['z']) - min(positions['z']))**2
                )
            }

        return rom_analysis

    def generate_analytics_report(self, skeleton_data: Dict) -> Dict:
        """
        Generate comprehensive analytics report

        Returns:
            Complete analytics including heat maps, motion trails, power moments
        """
        return {
            "motion_trails": {
                joint: [{"x": p.x, "y": p.y, "t": p.timestamp, "v": p.velocity}
                       for p in self.generate_motion_trail(skeleton_data, joint, 200)]
                for joint in ["nose", "right_hand", "left_hand", "right_foot", "left_foot"]
            },
            "power_moments": self.detect_power_moments(skeleton_data),
            "range_of_motion": self.analyze_range_of_motion(skeleton_data),
            "velocity_profiles": {
                joint: self.calculate_joint_velocity_profile(skeleton_data, joint)
                for joint in ["right_hand", "left_hand"]
            }
        }


# Global analytics instance
analytics = AdvancedAnalytics()

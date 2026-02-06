"""
Test skeleton editor API
"""

import sys
from pathlib import Path
import requests
import json

# Test configuration
API_BASE = "http://localhost:8080"
VIDEO_PATH = str(Path(__file__).parent / "test_video.mp4")
SKELETON_PATH = str(Path(__file__).parent / "test_skeleton.json")


def test_api():
    """Test skeleton editor API endpoints"""
    print("Testing Skeleton Editor API...")
    print(f"API Base: {API_BASE}")
    print(f"Video: {VIDEO_PATH}")
    print(f"Skeleton: {SKELETON_PATH}")
    print()

    try:
        # Test 1: API root
        print("[TEST 1] GET / (API root)")
        response = requests.get(f"{API_BASE}/")
        assert response.status_code == 200, f"Expected 200, got {response.status_code}"
        data = response.json()
        print(f"[PASS] API name: {data['name']}, version: {data['version']}")
        print()

        # Test 2: Create project
        print("[TEST 2] POST /api/projects (create project)")
        response = requests.post(
            f"{API_BASE}/api/projects",
            params={
                "video_path": VIDEO_PATH,
                "skeleton_path": SKELETON_PATH
            }
        )
        assert response.status_code == 200, f"Expected 200, got {response.status_code}"
        data = response.json()
        project_id = data['project_id']
        print(f"[PASS] Project created: {project_id}")
        print(f"  - Video: {data['video_info']['width']}x{data['video_info']['height']}, {data['video_info']['total_frames']} frames")
        print(f"  - Skeleton: {data['skeleton_info']['total_landmarks']} landmarks, {data['skeleton_info']['frames_count']} frames")
        print()

        # Test 3: Get project info
        print("[TEST 3] GET /api/projects/{project_id}/info")
        response = requests.get(f"{API_BASE}/api/projects/{project_id}/info")
        assert response.status_code == 200, f"Expected 200, got {response.status_code}"
        data = response.json()
        print(f"[PASS] Project info retrieved")
        print()

        # Test 4: Get skeleton for frame 0
        print("[TEST 4] GET /api/projects/{project_id}/skeleton/0")
        response = requests.get(f"{API_BASE}/api/projects/{project_id}/skeleton/0")
        assert response.status_code == 200, f"Expected 200, got {response.status_code}"
        data = response.json()
        print(f"[PASS] Frame 0 skeleton retrieved")
        print(f"  - Body: {len(data['body'])} landmarks")
        print(f"  - Left hand: {len(data['left_hand'])} landmarks")
        print(f"  - Right hand: {len(data['right_hand'])} landmarks")
        print()

        # Test 5: Get frame image (no overlay)
        print("[TEST 5] GET /api/projects/{project_id}/frame/0 (no overlay)")
        response = requests.get(f"{API_BASE}/api/projects/{project_id}/frame/0")
        assert response.status_code == 200, f"Expected 200, got {response.status_code}"
        assert response.headers['content-type'] == 'image/jpeg', f"Expected image/jpeg, got {response.headers['content-type']}"
        print(f"[PASS] Frame 0 image retrieved (size: {len(response.content)} bytes)")
        print()

        # Test 6: Get frame image (with overlay)
        print("[TEST 6] GET /api/projects/{project_id}/frame/0 (with overlay)")
        response = requests.get(
            f"{API_BASE}/api/projects/{project_id}/frame/0",
            params={"show_overlay": True, "show_body": True, "show_hands": True}
        )
        assert response.status_code == 200, f"Expected 200, got {response.status_code}"
        print(f"[PASS] Frame 0 with overlay retrieved (size: {len(response.content)} bytes)")
        print()

        # Test 7: Get quality metrics
        print("[TEST 7] GET /api/projects/{project_id}/quality")
        response = requests.get(f"{API_BASE}/api/projects/{project_id}/quality")
        assert response.status_code == 200, f"Expected 200, got {response.status_code}"
        data = response.json()
        print(f"[PASS] Quality metrics retrieved")
        print(f"  - Total frames: {data['total_frames']}")
        print(f"  - Body detection rate: {data['body_detection_rate']:.2%}")
        print(f"  - Left hand detection rate: {data['left_hand_detection_rate']:.2%}")
        print(f"  - Right hand detection rate: {data['right_hand_detection_rate']:.2%}")
        print(f"  - Avg body confidence: {data['avg_body_confidence']:.2f}")
        print(f"  - Quality: {data['quality_assessment']}")
        print()

        # Test 8: Close project
        print("[TEST 8] DELETE /api/projects/{project_id}")
        response = requests.delete(f"{API_BASE}/api/projects/{project_id}")
        assert response.status_code == 200, f"Expected 200, got {response.status_code}"
        print(f"[PASS] Project closed")
        print()

        print("[SUCCESS] All API tests passed!")
        print("\nAPI is ready for use!")
        print(f"  - API docs: {API_BASE}/docs")
        print(f"  - ReDoc: {API_BASE}/redoc")

        return True

    except requests.exceptions.ConnectionError:
        print("[ERROR] Could not connect to API server")
        print(f"  - Make sure the API is running: python skeleton_editor_api.py")
        print(f"  - Or: uvicorn skeleton_editor_api:app --port 8080")
        return False

    except AssertionError as e:
        print(f"[FAIL] {e}")
        return False

    except Exception as e:
        print(f"[ERROR] {e}")
        import traceback
        traceback.print_exc()
        return False


if __name__ == '__main__':
    success = test_api()
    sys.exit(0 if success else 1)

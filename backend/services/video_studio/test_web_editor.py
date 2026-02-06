"""
Test web editor frontend accessibility
"""

import sys
import requests
import time

API_BASE = "http://localhost:8080"


def test_web_editor():
    """Test that web editor is accessible and functional"""
    print("Testing Web Editor Frontend...")
    print(f"API Base: {API_BASE}")
    print()

    try:
        # Test 1: Load HTML page
        print("[TEST 1] GET / (HTML page)")
        response = requests.get(f"{API_BASE}/")
        assert response.status_code == 200, f"Expected 200, got {response.status_code}"
        assert 'text/html' in response.headers.get('content-type', ''), "Expected HTML content"
        assert 'Skeleton Editor' in response.text, "Expected 'Skeleton Editor' in HTML"
        print(f"[PASS] HTML page loaded successfully")
        print(f"  - Content type: {response.headers.get('content-type')}")
        print(f"  - Size: {len(response.content)} bytes")
        print()

        # Test 2: Load JavaScript file
        print("[TEST 2] GET /skeleton_editor.js (JavaScript)")
        response = requests.get(f"{API_BASE}/skeleton_editor.js")
        assert response.status_code == 200, f"Expected 200, got {response.status_code}"
        assert 'javascript' in response.headers.get('content-type', ''), "Expected JavaScript content"
        assert 'SkeletonEditor' in response.text, "Expected 'SkeletonEditor' class in JS"
        print(f"[PASS] JavaScript file loaded successfully")
        print(f"  - Content type: {response.headers.get('content-type')}")
        print(f"  - Size: {len(response.content)} bytes")
        print()

        # Test 3: API endpoints still working
        print("[TEST 3] API endpoints check")

        # Create project
        video_path = r"C:\Users\utente\Desktop\cursor\Progetto_media_center\MediaCenter_Modular\modules\video_studio\src\test_video.mp4"
        skeleton_path = r"C:\Users\utente\Desktop\cursor\Progetto_media_center\MediaCenter_Modular\modules\video_studio\src\test_skeleton.json"

        response = requests.post(
            f"{API_BASE}/api/projects",
            params={
                "video_path": video_path,
                "skeleton_path": skeleton_path
            }
        )
        assert response.status_code == 200, f"Expected 200, got {response.status_code}"
        data = response.json()
        project_id = data['project_id']
        print(f"[PASS] Project created: {project_id}")

        # Get quality metrics
        response = requests.get(f"{API_BASE}/api/projects/{project_id}/quality")
        assert response.status_code == 200, f"Expected 200, got {response.status_code}"
        quality = response.json()
        print(f"[PASS] Quality metrics retrieved")
        print(f"  - Total frames: {quality['total_frames']}")
        print(f"  - Quality: {quality['quality_assessment']}")

        # Get frame with skeleton
        response = requests.get(
            f"{API_BASE}/api/projects/{project_id}/frame/0",
            params={"show_overlay": False}
        )
        assert response.status_code == 200, f"Expected 200, got {response.status_code}"
        assert response.headers['content-type'] == 'image/jpeg', "Expected JPEG image"
        print(f"[PASS] Frame image retrieved (size: {len(response.content)} bytes)")

        # Close project
        response = requests.delete(f"{API_BASE}/api/projects/{project_id}")
        assert response.status_code == 200, f"Expected 200, got {response.status_code}"
        print(f"[PASS] Project closed")
        print()

        # Success summary
        print("="*60)
        print("[SUCCESS] All web editor tests passed!")
        print("="*60)
        print()
        print("WEB EDITOR IS READY TO USE!")
        print()
        print(f"  URL: {API_BASE}")
        print(f"  Open in browser to use the editor")
        print()
        print("Features available:")
        print("  - Video playback with skeleton overlay")
        print("  - Frame-by-frame navigation (arrows, timeline)")
        print("  - Quality metrics dashboard")
        print("  - Play/Pause (SPACE key)")
        print("  - Toggle skeleton/body/hands")
        print("  - Keyboard shortcuts (LEFT/RIGHT arrows)")
        print()

        return True

    except requests.exceptions.ConnectionError:
        print("[ERROR] Could not connect to server")
        print(f"  - Make sure server is running on {API_BASE}")
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
    success = test_web_editor()
    sys.exit(0 if success else 1)

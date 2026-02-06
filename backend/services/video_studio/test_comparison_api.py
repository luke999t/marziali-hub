import sys
import time
import requests
from pathlib import Path

API_BASE = "http://localhost:8081"
TEST_VIDEO = r"C:\Users\utente\Desktop\cursor\Progetto_media_center\MediaCenter_Modular\modules\video_studio\src\test_video.mp4"

def test_comparison_api():
    print("=" * 80)
    print("COMPARISON API TEST")
    print("=" * 80)
    print()

    if not Path(TEST_VIDEO).exists():
        print(f"[ERROR] Test video not found: {TEST_VIDEO}")
        return False

    try:
        print("[1/6] Uploading first video...")
        with open(TEST_VIDEO, 'rb') as f:
            files = {'video_file': ('test_video_1.mp4', f, 'video/mp4')}
            data = {
                'maestro_name': 'Master A',
                'martial_art_style': 'tai_chi',
                'project_name': 'Comparison Test Project',
            }
            response = requests.post(f"{API_BASE}/api/upload", files=files, data=data)

        assert response.status_code == 200
        result1 = response.json()
        video_id_1 = result1['video_id']
        project_id = result1['project_id']
        print(f"[PASS] Video 1 uploaded: {video_id_1}")
        print()

        print("[2/6] Uploading second video...")
        with open(TEST_VIDEO, 'rb') as f:
            files = {'video_file': ('test_video_2.mp4', f, 'video/mp4')}
            data = {
                'maestro_name': 'Master B',
                'martial_art_style': 'tai_chi',
                'project_id': project_id,
            }
            response = requests.post(f"{API_BASE}/api/upload", files=files, data=data)

        assert response.status_code == 200
        result2 = response.json()
        video_id_2 = result2['video_id']
        print(f"[PASS] Video 2 uploaded: {video_id_2}")
        print()

        print("[3/6] Waiting for skeleton processing...")
        max_wait = 120
        elapsed = 0
        videos_completed = {video_id_1: False, video_id_2: False}

        while elapsed < max_wait:
            for vid in [video_id_1, video_id_2]:
                if not videos_completed[vid]:
                    response = requests.get(f"{API_BASE}/api/status/{vid}")
                    if response.status_code == 200:
                        status = response.json()
                        if status['status'] == 'completed':
                            print(f"[PASS] {vid} completed")
                            videos_completed[vid] = True
                        elif status['status'] == 'failed':
                            print(f"[FAIL] {vid} failed: {status['message']}")
                            return False

            if all(videos_completed.values()):
                break

            time.sleep(3)
            elapsed += 3

        if not all(videos_completed.values()):
            print("[WARN] Processing timeout")
            return False
        print()

        print("[4/6] Testing project videos endpoint...")
        response = requests.get(f"{API_BASE}/api/projects/{project_id}/videos")
        if response.status_code != 200:
            print(f"[ERROR] Status code: {response.status_code}")
            print(f"[ERROR] Response: {response.text}")
        assert response.status_code == 200
        videos_data = response.json()
        assert len(videos_data['videos']) >= 2
        print(f"[PASS] Found {len(videos_data['videos'])} completed videos")
        print()

        print("[5/6] Testing comparison without video output...")
        comparison_data = {
            'video_id_1': video_id_1,
            'video_id_2': video_id_2,
            'create_video_output': False
        }
        response = requests.post(f"{API_BASE}/api/compare", json=comparison_data)
        assert response.status_code == 200
        result = response.json()

        print(f"[PASS] Comparison completed:")
        print(f"  - Frames compared: {result['total_frames_compared']}")
        print(f"  - Average similarity: {result['average_similarity']:.1%}")
        print(f"  - Position error: {result['average_position_error']:.3f}")
        print(f"  - Synchronization: {result['average_synchronization']:.1%}")
        print()

        print("[6/6] Testing comparison with video output...")
        comparison_data['create_video_output'] = True
        response = requests.post(f"{API_BASE}/api/compare", json=comparison_data)
        assert response.status_code == 200
        result = response.json()

        print(f"[PASS] Comparison video created:")
        print(f"  - Output path: {result['comparison_video_path']}")
        print(f"  - Similarity: {result['average_similarity']:.1%}")
        print()

        print("=" * 80)
        print("[SUCCESS] ALL COMPARISON TESTS PASSED")
        print("=" * 80)
        print()

        return True

    except AssertionError as e:
        print(f"[FAIL] Assertion failed: {e}")
        import traceback
        traceback.print_exc()
        return False
    except Exception as e:
        print(f"[ERROR] {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == '__main__':
    success = test_comparison_api()
    sys.exit(0 if success else 1)

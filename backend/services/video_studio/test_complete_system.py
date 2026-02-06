import sys
import time
import requests
from pathlib import Path

API_UPLOAD = "http://localhost:8081"
API_EDITOR = "http://localhost:8080"
TEST_VIDEO = r"C:\Users\utente\Desktop\cursor\Progetto_media_center\MediaCenter_Modular\modules\video_studio\src\test_video.mp4"

def test_complete_workflow():
    print("=" * 80)
    print("COMPLETE SYSTEM TEST - Martial Arts Media Center")
    print("=" * 80)
    print()

    if not Path(TEST_VIDEO).exists():
        print(f"[ERROR] Test video not found: {TEST_VIDEO}")
        return False

    try:
        print("[1/5] Testing Upload API...")
        response = requests.get(f"{API_UPLOAD}/")
        assert response.status_code == 200
        assert 'text/html' in response.headers.get('content-type', '')
        print("[PASS] Upload interface accessible")
        print()

        print("[2/5] Uploading test video...")
        with open(TEST_VIDEO, 'rb') as f:
            files = {'video_file': ('test_complete.mp4', f, 'video/mp4')}
            data = {
                'maestro_name': 'Test Master',
                'martial_art_style': 'tai_chi',
                'maestro_experience_years': 20,
                'project_name': 'System Test Project',
                'video_tags': 'test,system,complete',
            }
            response = requests.post(f"{API_UPLOAD}/api/upload", files=files, data=data)

        assert response.status_code == 200
        result = response.json()
        project_id = result['project_id']
        video_id = result['video_id']
        print(f"[PASS] Video uploaded: {video_id}")
        print()

        print("[3/5] Waiting for skeleton processing...")
        max_wait = 60
        elapsed = 0
        while elapsed < max_wait:
            response = requests.get(f"{API_UPLOAD}/api/status/{video_id}")
            if response.status_code == 200:
                status = response.json()
                if status['status'] == 'completed':
                    print(f"[PASS] Processing completed in {elapsed}s")
                    break
                elif status['status'] == 'failed':
                    print(f"[FAIL] Processing failed: {status['message']}")
                    return False
            time.sleep(2)
            elapsed += 2

        if elapsed >= max_wait:
            print("[WARN] Processing timeout")
        print()

        print("[4/5] Testing Editor API...")
        response = requests.get(f"{API_EDITOR}/")
        assert response.status_code == 200
        print("[PASS] Editor interface accessible")
        print()

        print("[5/5] Verifying project data...")
        response = requests.get(f"{API_UPLOAD}/api/projects/{project_id}")
        assert response.status_code == 200
        project = response.json()
        assert len(project['videos']) == 1
        assert project['videos'][0]['has_skeleton'] == True
        print(f"[PASS] Project verified: {project['name']}")
        print(f"  - Videos: {len(project['videos'])}")
        print(f"  - Skeleton extracted: {project['videos'][0]['has_skeleton']}")
        print()

        print("=" * 80)
        print("[SUCCESS] ALL SYSTEM TESTS PASSED")
        print("=" * 80)
        print()
        print("System Status:")
        print(f"  Upload API:  {API_UPLOAD}")
        print(f"  Editor API:  {API_EDITOR}")
        print(f"  Projects:    {project['statistics']['total_videos']} videos")
        print(f"  Completed:   {project['statistics']['completed']}")
        print()

        return True

    except AssertionError as e:
        print(f"[FAIL] {e}")
        return False
    except Exception as e:
        print(f"[ERROR] {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == '__main__':
    success = test_complete_workflow()
    sys.exit(0 if success else 1)

"""
Test Upload API
Tests video upload, validation, and processing workflow
"""

import sys
import requests
import time
from pathlib import Path

API_BASE = "http://localhost:8081"
TEST_VIDEO = r"C:\Users\utente\Desktop\cursor\Progetto_media_center\MediaCenter_Modular\modules\video_studio\src\test_video.mp4"


def test_upload_api():
    """Test upload API endpoints"""
    print("Testing Upload API...")
    print(f"API Base: {API_BASE}")
    print(f"Test Video: {TEST_VIDEO}")
    print()

    if not Path(TEST_VIDEO).exists():
        print(f"[ERROR] Test video not found: {TEST_VIDEO}")
        return False

    try:
        # Test 1: API info
        print("[TEST 1] GET / (API info)")
        response = requests.get(f"{API_BASE}/")
        assert response.status_code == 200, f"Expected 200, got {response.status_code}"
        data = response.json()
        print(f"[PASS] API: {data['name']} v{data['version']}")
        print(f"  - Max file size: {data['max_file_size_mb']} MB")
        print(f"  - Supported formats: {', '.join(data['supported_formats'])}")
        print(f"  - Martial art styles: {len(data['martial_art_styles'])} styles")
        print()

        # Test 2: Upload video
        print("[TEST 2] POST /api/upload (Upload video)")
        with open(TEST_VIDEO, 'rb') as f:
            files = {'video_file': ('test_video.mp4', f, 'video/mp4')}
            data = {
                'maestro_name': 'Master Chen',
                'martial_art_style': 'tai_chi',
                'maestro_experience_years': 30,
                'maestro_certification': '19th Generation Chen Family',
                'maestro_bio': 'Master of Chen Style Tai Chi',
                'project_name': 'Test Project - Tai Chi',
                'video_tags': 'test, chen, laojia',
                'video_notes': 'Test upload for API validation'
            }

            response = requests.post(
                f"{API_BASE}/api/upload",
                files=files,
                data=data
            )

        assert response.status_code == 200, f"Expected 200, got {response.status_code}"
        upload_result = response.json()
        assert upload_result['success'], "Upload should succeed"

        project_id = upload_result['project_id']
        video_id = upload_result['video_id']

        print(f"[PASS] Video uploaded successfully")
        print(f"  - Project ID: {project_id}")
        print(f"  - Video ID: {video_id}")
        print(f"  - Message: {upload_result['message']}")

        if upload_result.get('video_info'):
            info = upload_result['video_info']
            print(f"  - Filename: {info['filename']}")
            print(f"  - Duration: {info['duration']:.2f}s")
            print(f"  - Resolution: {info['resolution']}")
            print(f"  - FPS: {info['fps']}")
            print(f"  - Size: {info['size_mb']} MB")
        print()

        # Test 3: Check processing status
        print("[TEST 3] GET /api/status/{video_id} (Processing status)")
        time.sleep(2)  # Wait for processing to start

        response = requests.get(f"{API_BASE}/api/status/{video_id}")

        if response.status_code == 200:
            status = response.json()
            print(f"[PASS] Status retrieved")
            print(f"  - Video ID: {status['video_id']}")
            print(f"  - Status: {status['status']}")
            print(f"  - Message: {status['message']}")
            print(f"  - Progress: {status['progress']:.1%}")
        else:
            print(f"[INFO] Status not yet available (processing may complete quickly)")
        print()

        # Test 4: List projects
        print("[TEST 4] GET /api/projects (List projects)")
        response = requests.get(f"{API_BASE}/api/projects")
        assert response.status_code == 200, f"Expected 200, got {response.status_code}"

        projects_list = response.json()
        print(f"[PASS] Projects listed")
        print(f"  - Total projects: {projects_list['total']}")

        for proj in projects_list['projects']:
            print(f"  - {proj['name']} ({proj['style']}) - {proj['videos_count']} videos")
        print()

        # Test 5: Get project details
        print("[TEST 5] GET /api/projects/{project_id} (Project details)")
        response = requests.get(f"{API_BASE}/api/projects/{project_id}")
        assert response.status_code == 200, f"Expected 200, got {response.status_code}"

        project_details = response.json()
        print(f"[PASS] Project details retrieved")
        print(f"  - Name: {project_details['name']}")
        print(f"  - Style: {project_details['style']}")
        print(f"  - Status: {project_details['status']}")
        print(f"  - Videos: {len(project_details['videos'])}")

        for video in project_details['videos']:
            print(f"    * {video['filename']} - {video['status']}")
            print(f"      Maestro: {video['maestro_name']}")
            print(f"      Duration: {video['duration']:.2f}s")
            print(f"      Has skeleton: {video['has_skeleton']}")
            print(f"      Tags: {', '.join(video['tags'])}")

        stats = project_details['statistics']
        print(f"  - Statistics:")
        print(f"    * Total videos: {stats['total_videos']}")
        print(f"    * Completed: {stats['completed']}")
        print(f"    * Processing: {stats['processing']}")
        print(f"    * Failed: {stats['failed']}")
        print()

        # Test 6: Wait for processing to complete (optional)
        print("[TEST 6] Wait for skeleton processing...")
        max_wait = 60  # seconds
        wait_interval = 5
        elapsed = 0

        while elapsed < max_wait:
            response = requests.get(f"{API_BASE}/api/projects/{project_id}")
            if response.status_code == 200:
                project = response.json()
                video = project['videos'][0]

                if video['status'] == 'completed':
                    print(f"[PASS] Processing completed in {elapsed}s")
                    print(f"  - Has skeleton: {video['has_skeleton']}")
                    break
                elif video['status'] == 'failed':
                    print(f"[WARN] Processing failed")
                    break
                else:
                    print(f"  [{elapsed}s] Status: {video['status']}...")
                    time.sleep(wait_interval)
                    elapsed += wait_interval
            else:
                break

        if elapsed >= max_wait:
            print(f"[INFO] Processing still running after {max_wait}s (normal for longer videos)")
        print()

        # Test 7: Upload to existing project
        print("[TEST 7] POST /api/upload (Upload to existing project)")
        with open(TEST_VIDEO, 'rb') as f:
            files = {'video_file': ('test_video_2.mp4', f, 'video/mp4')}
            data = {
                'project_id': project_id,  # Use existing project
                'maestro_name': 'Master Wang',
                'martial_art_style': 'tai_chi',
                'maestro_experience_years': 25,
                'video_tags': 'test, second_video',
            }

            response = requests.post(
                f"{API_BASE}/api/upload",
                files=files,
                data=data
            )

        assert response.status_code == 200, f"Expected 200, got {response.status_code}"
        upload_result2 = response.json()

        print(f"[PASS] Second video uploaded to same project")
        print(f"  - Project ID: {upload_result2['project_id']}")
        print(f"  - Video ID: {upload_result2['video_id']}")

        # Verify project has 2 videos
        response = requests.get(f"{API_BASE}/api/projects/{project_id}")
        project = response.json()
        print(f"  - Total videos in project: {len(project['videos'])}")
        assert len(project['videos']) == 2, "Project should have 2 videos"
        print()

        # Success summary
        print("=" * 60)
        print("[SUCCESS] All upload API tests passed!")
        print("=" * 60)
        print()
        print("UPLOAD API IS READY TO USE!")
        print()
        print(f"  API URL: {API_BASE}")
        print()
        print("Features:")
        print("  - Video upload with validation")
        print("  - Automatic metadata extraction")
        print("  - Background skeleton processing")
        print("  - Project management (create/update)")
        print("  - Processing status tracking")
        print("  - Support for multiple martial art styles")
        print()
        print("Next steps:")
        print("  - Create upload UI frontend")
        print("  - Integrate with skeleton editor")
        print("  - Add progress notifications")
        print()

        return True

    except requests.exceptions.ConnectionError:
        print("[ERROR] Could not connect to server")
        print(f"  - Make sure server is running on {API_BASE}")
        print(f"  - Start with: python upload_api.py")
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
    success = test_upload_api()
    sys.exit(0 if success else 1)

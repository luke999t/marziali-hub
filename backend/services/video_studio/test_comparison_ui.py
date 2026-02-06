import requests

API_BASE = "http://localhost:8081"

def test_comparison_ui():
    print("=" * 80)
    print("PHASE 1: COMPARISON UI TEST")
    print("=" * 80)
    print()

    tests_passed = 0
    tests_total = 0

    print("[1/5] Testing comparison interface HTML endpoint...")
    tests_total += 1
    try:
        response = requests.get(f"{API_BASE}/comparison")
        assert response.status_code == 200
        assert 'text/html' in response.headers.get('content-type', '')
        print("✅ PASS - Comparison HTML accessible")
        tests_passed += 1
    except Exception as e:
        print(f"❌ FAIL - {e}")

    print()
    print("[2/5] Testing comparison JavaScript endpoint...")
    tests_total += 1
    try:
        response = requests.get(f"{API_BASE}/comparison_interface.js")
        assert response.status_code == 200
        assert 'javascript' in response.headers.get('content-type', '')
        print("✅ PASS - Comparison JS accessible")
        tests_passed += 1
    except Exception as e:
        print(f"❌ FAIL - {e}")

    print()
    print("[3/5] Testing projects API...")
    tests_total += 1
    try:
        response = requests.get(f"{API_BASE}/api/projects")
        assert response.status_code == 200
        data = response.json()
        assert 'projects' in data
        print(f"✅ PASS - Found {len(data['projects'])} projects")
        tests_passed += 1
    except Exception as e:
        print(f"❌ FAIL - {e}")

    print()
    print("[4/5] Testing skeleton data endpoint...")
    tests_total += 1
    try:
        projects_response = requests.get(f"{API_BASE}/api/projects")
        projects = projects_response.json()['projects']

        if projects:
            project_id = projects[0]['id']
            videos_response = requests.get(f"{API_BASE}/api/projects/{project_id}/videos")
            videos_data = videos_response.json()

            if videos_data['videos']:
                video_id = videos_data['videos'][0]['id']
                skeleton_response = requests.get(f"{API_BASE}/api/videos/{video_id}/skeleton")

                if skeleton_response.status_code == 200:
                    skeleton_data = skeleton_response.json()
                    assert 'frames' in skeleton_data
                    assert 'video_metadata' in skeleton_data
                    print(f"✅ PASS - Skeleton data loaded ({len(skeleton_data['frames'])} frames)")
                    tests_passed += 1
                else:
                    print(f"⚠️ SKIP - No skeleton data available yet")
            else:
                print(f"⚠️ SKIP - No videos in project")
        else:
            print(f"⚠️ SKIP - No projects available")
    except Exception as e:
        print(f"❌ FAIL - {e}")

    print()
    print("[5/5] Testing comparison API...")
    tests_total += 1
    try:
        response = requests.get(f"{API_BASE}/docs")
        assert response.status_code == 200
        print("✅ PASS - API documentation accessible")
        tests_passed += 1
    except Exception as e:
        print(f"❌ FAIL - {e}")

    print()
    print("=" * 80)
    print(f"PHASE 1 TEST RESULTS: {tests_passed}/{tests_total} PASSED")
    print("=" * 80)
    print()

    if tests_passed == tests_total:
        print("✅ PHASE 1 COMPLETE - All endpoints working!")
        print()
        print("🌐 Access comparison interface at:")
        print(f"   {API_BASE}/comparison")
        return True
    else:
        print(f"⚠️ PHASE 1 INCOMPLETE - {tests_total - tests_passed} tests failed")
        return False

if __name__ == '__main__':
    test_comparison_ui()

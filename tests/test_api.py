# tests/test_api.py - UPDATED for mock_api.py
import sys
import os

# Add paths
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

try:
    from fastapi.testclient import TestClient
    from mock_api import app
    HAS_FASTAPI = True
except ImportError as e:
    print(f"⚠️  Import error: {e}")
    print("Install with: pip install fastapi httpx")
    HAS_FASTAPI = False
    exit(1)

client = TestClient(app)

def run_tests():
    print("🧪 Running API Tests (Mock Mode)...\n")
    passed = 0
    failed = 0

    # Test 1: Root endpoint
    print("Test 1: GET /")
    try:
        response = client.get("/")
        assert response.status_code == 200
        data = response.json()
        assert data["name"] == "NeuroShield API (MOCK)"
        print("   ✅ PASS")
        passed += 1
    except Exception as e:
        print(f"   ❌ FAIL: {e}")
        failed += 1

    # Test 2: Analyze suspicious sequence
    print("\nTest 2: POST /analyze (suspicious sequence)")
    try:
        response = client.post(
            "/analyze",
            json={
                "sequence": ["open", "read", "encrypt", "write", "unlink"],
                "context": {"is_privileged": True}
            }
        )
        assert response.status_code == 200
        data = response.json()
        assert "threat_score" in data
        assert "is_threat" in data
        print(f"   ✅ PASS - Threat score: {data.get('threat_score', 'N/A'):.3f}")
        print(f"   Is Threat: {data.get('is_threat')}")
        passed += 1
    except Exception as e:
        print(f"   ❌ FAIL: {e}")
        failed += 1

    # Test 3: Analyze normal sequence
    print("\nTest 3: POST /analyze (normal sequence)")
    try:
        response = client.post(
            "/analyze",
            json={
                "sequence": ["open", "read", "write", "close"],
                "context": {}
            }
        )
        assert response.status_code == 200
        data = response.json()
        print(f"   ✅ PASS - Threat score: {data.get('threat_score', 'N/A'):.3f}")
        print(f"   Is Threat: {data.get('is_threat')}")
        passed += 1
    except Exception as e:
        print(f"   ❌ FAIL: {e}")
        failed += 1

    # Test 4: Status endpoint
    print("\nTest 4: GET /status")
    try:
        response = client.get("/status")
        assert response.status_code == 200
        data = response.json()
        assert "status" in data
        print(f"   ✅ PASS - Status: {data.get('status')}")
        passed += 1
    except Exception as e:
        print(f"   ❌ FAIL: {e}")
        failed += 1

    # Test 5: Threats endpoint
    print("\nTest 5: GET /threats")
    try:
        response = client.get("/threats")
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list)
        print(f"   ✅ PASS - {len(data)} threats found")
        passed += 1
    except Exception as e:
        print(f"   ❌ FAIL: {e}")
        failed += 1

    # Test 6: Feedback endpoint
    print("\nTest 6: POST /feedback/false_positive")
    try:
        response = client.post(
            "/feedback/false_positive",
            json=["open", "read", "close", "open", "read", "close"]
        )
        assert response.status_code == 200
        data = response.json()
        print(f"   ✅ PASS - New threshold: {data.get('new_threshold')}")
        passed += 1
    except Exception as e:
        print(f"   ❌ FAIL: {e}")
        failed += 1

    # Test 7: Batch analyze
    print("\nTest 7: POST /analyze/batch")
    try:
        response = client.post(
            "/analyze/batch",
            json=[
                ["open", "read", "write", "close"],
                ["open", "read", "encrypt", "write", "unlink"]
            ]
        )
        assert response.status_code == 200
        data = response.json()
        assert "results" in data
        print(f"   ✅ PASS - {data.get('total')} sequences analyzed")
        passed += 1
    except Exception as e:
        print(f"   ❌ FAIL: {e}")
        failed += 1

    # Summary
    print(f"\n{'='*50}")
    print(f"Results: {passed} passed, {failed} failed")
    print(f"{'='*50}")
    return failed == 0

if __name__ == "__main__":
    success = run_tests()
    sys.exit(0 if success else 1)
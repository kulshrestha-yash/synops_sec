"""Test script to verify backend fixes for NeuroShield."""
import asyncio
import sys
from pathlib import Path

# Add api to path
sys.path.insert(0, str(Path(__file__).parent / "api"))

from server import app, startup
from fastapi.testclient import TestClient


async def test_startup():
    """Test startup function with error handling."""
    print("Testing startup()...")
    await startup()
    print("[OK] Startup completed without crash")


def test_health_endpoint():
    """Test enhanced /health endpoint."""
    print("\nTesting /health endpoint...")
    client = TestClient(app)
    response = client.get("/health")
    
    assert response.status_code == 200, f"Expected 200, got {response.status_code}"
    data = response.json()
    
    # Check new fields
    assert "model_loaded" in data, "Missing 'model_loaded' field"
    assert "ml_mode_active" in data, "Missing 'ml_mode_active' field"
    assert "startup_errors" in data, "Missing 'startup_errors' field"
    assert isinstance(data["startup_errors"], list), "startup_errors should be a list"
    
    print(f"  - status: {data['status']}")
    print(f"  - mode: {data['mode']}")
    print(f"  - model_loaded: {data['model_loaded']}")
    print(f"  - ml_mode_active: {data['ml_mode_active']}")
    print(f"  - startup_errors: {len(data['startup_errors'])} errors")
    print("[OK] /health endpoint enhanced correctly")


def test_analyze_endpoint():
    """Test /analyze endpoint with error handling."""
    print("\nTesting /analyze endpoint...")
    client = TestClient(app)
    
    # Valid request
    response = client.post("/analyze", json={
        "sequence": ["open", "read", "write", "close"],
        "context": {"privileged_process": False}
    })
    assert response.status_code == 200, f"Expected 200, got {response.status_code}"
    data = response.json()
    assert "threat_score" in data
    print(f"  - Valid request: threat_score={data['threat_score']:.3f}")
    
    # Invalid request (empty sequence)
    response = client.post("/analyze", json={"sequence": []})
    assert response.status_code == 400, f"Expected 400, got {response.status_code}"
    print("  - Empty sequence correctly rejected (400)")
    
    print("[OK] /analyze endpoint error handling works")


def test_batch_analyze_endpoint():
    """Test /analyze/batch endpoint with error handling."""
    print("\nTesting /analyze/batch endpoint...")
    client = TestClient(app)
    
    # Valid request
    response = client.post("/analyze/batch", json={
        "sequences": [
            ["open", "read"],
            ["connect", "send", "recv"]
        ]
    })
    assert response.status_code == 200, f"Expected 200, got {response.status_code}"
    data = response.json()
    assert "results" in data
    assert data["total"] == 2
    print(f"  - Batch analysis: {data['total']} sequences processed")
    
    # Invalid request (empty sequences)
    response = client.post("/analyze/batch", json={"sequences": []})
    assert response.status_code == 400, f"Expected 400, got {response.status_code}"
    print("  - Empty sequences correctly rejected (400)")
    
    print("[OK] /analyze/batch endpoint error handling works")


def test_mock_mode_fallback():
    """Test that mock mode fallback works."""
    print("\nTesting mock mode fallback...")
    client = TestClient(app)
    
    # Get status
    response = client.get("/status")
    assert response.status_code == 200
    data = response.json()
    
    print(f"  - Runtime mode: {data['mode']}")
    print(f"  - Status: {data['status']}")
    assert data["status"] == "operational"
    
    # Analyze should still work in mock mode
    response = client.post("/analyze", json={
        "sequence": ["encrypt", "connect", "inject"]
    })
    assert response.status_code == 200
    result = response.json()
    print(f"  - Mock analysis works: threat_score={result['threat_score']:.3f}")
    
    print("[OK] Mock mode fallback functional")


def main():
    """Run all tests."""
    print("=" * 60)
    print("Backend Fixes Verification Test")
    print("=" * 60)
    
    try:
        # Run async startup test
        asyncio.run(test_startup())
        
        # Run synchronous tests
        test_health_endpoint()
        test_analyze_endpoint()
        test_batch_analyze_endpoint()
        test_mock_mode_fallback()
        
        print("\n" + "=" * 60)
        print("[SUCCESS] All backend fixes verified!")
        print("=" * 60)
        return 0
        
    except AssertionError as e:
        print(f"\n[FAILED] Assertion error: {e}")
        return 1
    except Exception as e:
        print(f"\n[ERROR] Unexpected error: {type(e).__name__}: {e}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())

"""Test script to verify NeuroShield server endpoints."""
import requests
import time
import subprocess
import sys

def test_health_endpoint():
    """Test the /health endpoint shows ML mode status."""
    try:
        response = requests.get("http://localhost:8000/health", timeout=5)
        if response.status_code == 200:
            data = response.json()
            print(f"\n{'='*60}")
            print("HEALTH ENDPOINT RESPONSE:")
            print(f"{'='*60}")
            print(f"Status: {data.get('status')}")
            print(f"Mode: {data.get('mode')}")
            print(f"ML Enabled: {data.get('ml_enabled')}")
            print(f"\nComponents:")
            for component, info in data.get('components', {}).items():
                if isinstance(info, dict):
                    print(f"  - {component}: {info.get('status')} - {info.get('description', '')}")
                else:
                    print(f"  - {component}: {info}")
            
            if data.get('startup_errors'):
                print(f"\nStartup Errors:")
                for error in data['startup_errors']:
                    print(f"  - {error}")
            else:
                print(f"\nMessage: {data.get('message', 'No message')}")
            
            print(f"{'='*60}\n")
            return True
        else:
            print(f"[ERROR] Health check failed with status {response.status_code}")
            return False
    except Exception as e:
        print(f"[ERROR] Failed to connect: {e}")
        return False

def test_analyze_endpoint():
    """Test the /analyze endpoint with error handling."""
    try:
        # Test with valid data
        response = requests.post(
            "http://localhost:8000/analyze",
            json={"sequence": ["open", "read", "connect", "encrypt"], "context": {}},
            timeout=5
        )
        if response.status_code == 200:
            print("[OK] /analyze endpoint working correctly")
            data = response.json()
            print(f"  Threat Score: {data.get('threat_score')}")
            print(f"  Is Threat: {data.get('is_threat')}")
            print(f"  Severity: {data.get('severity')}")
            return True
        else:
            print(f"[ERROR] Analyze failed with status {response.status_code}")
            return False
    except Exception as e:
        print(f"[ERROR] Analyze request failed: {e}")
        return False

def test_error_handling():
    """Test error handling with invalid data."""
    try:
        # Test with empty sequence
        response = requests.post(
            "http://localhost:8000/analyze",
            json={"sequence": [], "context": {}},
            timeout=5
        )
        if response.status_code == 400:
            print("[OK] Error handling works - empty sequence rejected")
            return True
        else:
            print(f"[WARNING] Expected 400 error, got {response.status_code}")
            return False
    except Exception as e:
        print(f"[ERROR] Error handling test failed: {e}")
        return False

if __name__ == "__main__":
    print("Testing NeuroShield API endpoints...")
    print("Make sure the server is running on port 8000")
    print("Run in another terminal: python api/server.py")
    print("\nWaiting 2 seconds before testing...")
    time.sleep(2)
    
    tests_passed = 0
    tests_total = 3
    
    if test_health_endpoint():
        tests_passed += 1
    
    if test_analyze_endpoint():
        tests_passed += 1
    
    if test_error_handling():
        tests_passed += 1
    
    print(f"\n{'='*60}")
    print(f"TESTS PASSED: {tests_passed}/{tests_total}")
    print(f"{'='*60}\n")
    
    sys.exit(0 if tests_passed == tests_total else 1)

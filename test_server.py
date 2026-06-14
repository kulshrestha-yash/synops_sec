"""Quick diagnostic script to test NeuroShield server."""

import sys
import time
import requests
from pathlib import Path

API_BASE = "http://localhost:8000"

def test_api():
    """Test if API is responding."""
    print("Testing NeuroShield API...")
    print(f"API Base: {API_BASE}\n")
    
    tests = [
        ("Root Endpoint", "/"),
        ("Health Check", "/health"),
        ("Status", "/status"),
        ("Dashboard", "/dashboard/"),
    ]
    
    results = []
    
    for name, endpoint in tests:
        url = f"{API_BASE}{endpoint}"
        try:
            response = requests.get(url, timeout=5)
            status = "✅ OK" if response.status_code == 200 else f"⚠️ {response.status_code}"
            results.append((name, status, url))
            print(f"{status} - {name}: {url}")
            
            if endpoint == "/health":
                data = response.json()
                print(f"     Mode: {data.get('mode', 'unknown')}")
                print(f"     ML Enabled: {data.get('ml_enabled', False)}")
                
        except requests.exceptions.ConnectionError:
            results.append((name, "❌ Connection Failed", url))
            print(f"❌ Connection Failed - {name}: {url}")
        except Exception as e:
            results.append((name, f"❌ Error: {e}", url))
            print(f"❌ Error - {name}: {str(e)[:50]}")
    
    print("\n" + "=" * 60)
    
    # Check dashboard files
    print("\nChecking Dashboard Files...")
    dashboard_dir = Path("dashboard")
    required = ["index.html", "styles.css", "app.js"]
    
    for filename in required:
        filepath = dashboard_dir / filename
        if filepath.exists():
            size = filepath.stat().st_size
            print(f"✅ {filename} ({size:,} bytes)")
        else:
            print(f"❌ {filename} - MISSING")
    
    print("\n" + "=" * 60)
    
    # Summary
    successful = sum(1 for _, status, _ in results if "OK" in status)
    print(f"\nSummary: {successful}/{len(results)} tests passed")
    
    if successful == len(results):
        print("\n🎉 All systems operational!")
        print("\n📍 Open in browser: http://localhost:8000/dashboard/")
    else:
        print("\n⚠️ Some tests failed. Check if server is running:")
        print("   python api/server.py")

if __name__ == "__main__":
    # Give server time to start if just launched
    time.sleep(1)
    test_api()

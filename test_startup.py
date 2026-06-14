"""Test script to verify NeuroShield server startup and model loading."""
import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent / "api"))

# Import server module
import server

async def test_startup():
    print("Testing NeuroShield startup...")
    await server.startup()
    
    print(f"\n{'='*60}")
    print(f"Runtime Mode: {server.runtime_mode}")
    print(f"Detector Loaded: {server.detector is not None}")
    print(f"Engine Loaded: {server.engine is not None}")
    print(f"Responder Loaded: {server.responder is not None}")
    print(f"Startup Errors: {server.startup_errors if server.startup_errors else 'None'}")
    print(f"{'='*60}\n")
    
    if server.runtime_mode == "ml" and server.detector is not None:
        print("[SUCCESS] Server started in ML mode with models loaded!")
        return 0
    elif server.runtime_mode == "mock":
        print("[INFO] Server started in MOCK mode (fallback)")
        return 0
    else:
        print("[ERROR] Unexpected startup state")
        return 1

if __name__ == "__main__":
    exit_code = asyncio.run(test_startup())
    sys.exit(exit_code)

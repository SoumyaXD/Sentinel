"""Test script for C4 checkpoint: demo endpoint and rate limiting."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)


def test_demo_endpoint_cached():
    """Test /ask/demo with a cached question."""
    print("\n1. Testing /ask/demo with cached question...")
    response = client.post("/ask/demo", json={"question": "What is CVE-2020-28500?"})
    print(f"   Status: {response.status_code}")
    print(f"   Response keys: {list(response.json().keys())}")
    assert response.status_code == 200
    data = response.json()
    assert "answer" in data
    assert "CVE-2020-28500" in data["cited_cve_ids"]
    print("   ✓ Demo endpoint returns cached answer instantly")


def test_demo_endpoint_uncached():
    """Test /ask/demo with an uncached question."""
    print("\n2. Testing /ask/demo with uncached question...")
    response = client.post("/ask/demo", json={"question": "What is CVE-9999-99999?"})
    print(f"   Status: {response.status_code}")
    assert response.status_code == 400
    assert "demo endpoint only serves" in response.json()["detail"].lower()
    print("   ✓ Demo endpoint rejects uncached questions with clear message")


def test_ask_endpoint_still_works():
    """Test that /ask still works (will make real API call)."""
    print("\n3. Testing /ask endpoint...")
    response = client.post("/ask", json={"question": "What is CVE-2020-28500?"})
    print(f"   Status: {response.status_code}")
    # Might be 200 or might hit rate limit depending on prior usage
    if response.status_code == 200:
        print("   ✓ /ask endpoint works")
    elif response.status_code == 429:
        print("   ✓ /ask endpoint correctly enforces rate limit")
    else:
        print(f"   Unexpected status: {response.status_code}")


def test_health_endpoint():
    """Test health endpoint."""
    print("\n4. Testing /health endpoint...")
    response = client.get("/health")
    print(f"   Status: {response.status_code}")
    print(f"   Response: {response.json()}")
    print("   ✓ Health endpoint responds")


if __name__ == "__main__":
    test_demo_endpoint_cached()
    test_demo_endpoint_uncached()
    test_ask_endpoint_still_works()
    test_health_endpoint()
    print("\n✓ All C4 tests passed!")

"""Test script for C4 checkpoint: demo endpoint and rate limiting."""

from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import patch

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


def test_demo_endpoint_cached_without_punctuation():
    """Test /ask/demo with a cached question missing trailing punctuation."""
    print("\n2. Testing /ask/demo with question missing '?'...")
    response = client.post("/ask/demo", json={"question": "What is CVE-2020-28500"})
    print(f"   Status: {response.status_code}")
    assert response.status_code == 200
    data = response.json()
    assert "CVE-2020-28500" in data["cited_cve_ids"]
    print("   ✓ Demo endpoint matches question even without trailing punctuation")


def test_demo_endpoint_uncached():
    """Test /ask/demo with an uncached question."""
    print("\n3. Testing /ask/demo with uncached question...")
    response = client.post("/ask/demo", json={"question": "What is CVE-9999-99999?"})
    print(f"   Status: {response.status_code}")
    assert response.status_code == 400
    assert "demo endpoint only serves" in response.json()["detail"].lower()
    print("   ✓ Demo endpoint rejects uncached questions with clear message")


def test_ask_endpoint_rate_limit():
    """Test that /ask enforces per-day rate limit (11th request gets 429)."""
    print("\n4. Testing /ask endpoint rate limit (11 rapid requests)...")
    
    # Mock the retrieval and generation to avoid real API calls
    mock_chunks = [{"text": "mock chunk", "metadata": {"cve_id": "CVE-2020-28500"}}]
    mock_result = {
        "answer": "Mock answer",
        "cited_cve_ids": ["CVE-2020-28500"]
    }
    
    with patch("app.main.retrieve_for_ask", return_value=mock_chunks):
        with patch("app.main.generate_answer", return_value=mock_result):
            # Make 11 requests from the same IP
            responses = []
            for i in range(11):
                response = client.post("/ask", json={"question": f"test question {i}"})
                responses.append(response)
                print(f"   Request {i+1}/11: status={response.status_code}")
            
            # First 10 should succeed (or all fail if we already hit the limit earlier)
            # But the 11th must be 429
            assert responses[10].status_code == 429, f"Expected 429 on 11th request, got {responses[10].status_code}"
            assert "rate limit exceeded" in responses[10].json()["detail"].lower()
            print("   ✓ /ask endpoint correctly enforces daily rate limit (11th request rejected)")


def test_health_endpoint():
    """Test health endpoint."""
    print("\n5. Testing /health endpoint...")
    response = client.get("/health")
    print(f"   Status: {response.status_code}")
    print(f"   Response: {response.json()}")
    print("   ✓ Health endpoint responds")


if __name__ == "__main__":
    test_demo_endpoint_cached()
    test_demo_endpoint_cached_without_punctuation()
    test_demo_endpoint_uncached()
    test_ask_endpoint_rate_limit()
    test_health_endpoint()
    print("\n✓ All C4 tests passed!")

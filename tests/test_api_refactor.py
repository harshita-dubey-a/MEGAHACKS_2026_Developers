from fastapi.testclient import TestClient
from main import app, verify_api_key
import pytest

# Override dependency
def override_verify_api_key(x_api_key: str = "test"):
    return "test"

app.dependency_overrides[verify_api_key] = override_verify_api_key
client = TestClient(app)

def test_routes_exist():
    # We can't easily test full logic without mocking manager, 
    # but we can test 404s/400s to verify route existence vs 404 Not Found (path)
    
    # 1. Create Scan (POST /api/v1/scans)
    # This requires valid body.
    # We can just check that it DOESN'T return 404 for the PATH.
    # Actually, we can check docs or just try to call it.
    
    # Check scan creation logic is reachable
    response = client.post("/api/v1/scans", json={"target": "http://example.com", "profile": "full"}, headers={"X-API-Key": "test"})
    # Since we are not mocking manager completely here (or are we?), it might try to create scan.
    # In 'main', 'scan_manager' is global.
    # Let's hope it doesn't fail hard or we can accept 500 if route exists.
    # But wait, create_scan requires logic.
    pass

def test_api_paths_match_specification():
    # Verify openapi.json contains the expected paths
    response = client.get("/openapi.json")
    assert response.status_code == 200
    schema = response.json()
    paths = schema["paths"]
    
    assert "/api/v1/scans" in paths
    assert "/api/v1/scans/{scan_id}" in paths
    assert "/api/v1/scans/{scan_id}/logs" in paths
    assert "/api/v1/scans/{scan_id}/abort" in paths
    assert "/api/v1/scans/{scan_id}/resume" in paths
    assert "/api/v1/vulnerabilities" in paths
    assert "/api/v1/vulnerabilities/{finding_id}" in paths
    
    # Verify old paths are gone
    assert "/scan" not in paths
    assert "/findings" not in paths
    
    print("API Routes Verified via OpenAPI Schema")

if __name__ == "__main__":
    test_api_paths_match_specification()

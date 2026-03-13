from fastapi.testclient import TestClient
from main import app
from unittest.mock import patch, AsyncMock

client = TestClient(app)

def test_nmap_endpoints():
    # Verify the router is mounted
    try:
        # Mocking start_scan to avoid actual execution
        with patch("routers.nmap.nmap_adapter.start_scan", new_callable=AsyncMock) as mock_scan:
            mock_scan.return_value = "37e2f8fc-c85f-46d3-90f0-5f5b5cedd379" # Valid UUID
            
            response = client.post(
                "/api/v1/nmap/scan",
                headers={"X-API-Key": "secret-api-key"},
                json={"target": "127.0.0.1"}
            )
            print(f"Scan Status: {response.status_code}")
            print(f"Scan Response: {response.json()}")
            assert response.status_code == 202
            assert response.json()["scan_id"] == "37e2f8fc-c85f-46d3-90f0-5f5b5cedd379"
            
        # Verify Results Endpoint
        with patch("routers.nmap.nmap_adapter.get_results", new_callable=AsyncMock) as mock_results:
            mock_results.return_value = [{"name": "Port 80", "severity": "info", "url": "127.0.0.1:80", "description": "Open port", "scanner": "nmap"}]
            
            response = client.get(
                "/api/v1/nmap/results/nmap-scan-uuid",
                headers={"X-API-Key": "secret-api-key"}
            )
            
            print(f"Results Status: {response.status_code}")
            print(f"Results: {response.json()}")
            assert response.status_code == 200
            assert len(response.json()) == 1
            assert response.json()[0]["scanner"] == "nmap"

        print("SUCCESS: Nmap endpoints Verified.")
    except Exception as e:
        print(f"FAILURE: {e}")
        raise

if __name__ == "__main__":
    test_nmap_endpoints()

from fastapi.testclient import TestClient
from main import app
import os
from unittest.mock import patch, AsyncMock, MagicMock

client = TestClient(app)

def test_mobsf_endpoints_exist():
    # Verify the router is mounted
    response = client.get("/api/v1/mobsf/status/123")
    assert response.status_code in [401, 403, 200, 404] 
    
    # Check scan endpoint (POST)
    with open("test.txt", "w") as f:
        f.write("dummy apk content")
        
    try:
        # Mocking the adapter methods to avoid external network calls and 500 errors
        # Python's patch on an instance method requires patching the class or the object where it's used.
        # In routers/mobsf.py: `mobsf_adapter` is instantiated at module level.
        # We need to patch `routers.mobsf.mobsf_adapter`
        
        with patch("routers.mobsf.mobsf_adapter.start_scan", new_callable=AsyncMock) as mock_scan:
            mock_scan.return_value = "37e2f8fc-c85f-46d3-90f0-5f5b5cedd378" # Valid UUID
            
            response = client.post(
                "/api/v1/mobsf/scan",
                headers={"X-API-Key": "secret-api-key"},
                files={"file": ("test.apk", open("test.txt", "rb"), "application/vnd.android.package-archive")}
            )
            
            print(f"Scan Status: {response.status_code}")
            print(f"Scan Response: {response.json()}")
            assert response.status_code == 202
            assert response.json()["scan_id"] == "37e2f8fc-c85f-46d3-90f0-5f5b5cedd378"
            
    finally:
        os.remove("test.txt")

def test_mobsf_report_endpoint():
    # Test Report Endpoint
    with patch("routers.mobsf.mobsf_adapter.get_report_pdf", new_callable=AsyncMock) as mock_report:
        mock_report.return_value = b"%PDF-1.4..."
        
        response = client.get(
            "/api/v1/mobsf/report/test-scan-id",
            headers={"X-API-Key": "secret-api-key"}
        )
        
        print(f"Report Status: {response.status_code}")
        # print(f"Report Content: {response.content}")
        
        # If 404, check detail (might be "Scan not found" if adapter logic checks memory)
        # Note: Adapter implementation checks `self._scans`.
        # Since using `patch` on the method, it bypasses the internal check IF the method implementation is fully mocked.
        # However, `get_report_pdf` implementation in `MobSFAdapter` DOES check `self._scans`.
        # If we mock `get_report_pdf` completely, it won't run that check.
        # It will just return the bytes.
        
        assert response.status_code == 200
        assert response.headers["content-type"] == "application/pdf"
        assert response.content == b"%PDF-1.4..."
        print("SUCCESS: Report endpoint works.")

if __name__ == "__main__":
    test_mobsf_endpoints_exist()
    test_mobsf_report_endpoint()

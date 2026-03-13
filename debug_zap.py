
import httpx
import asyncio

# Testing HTTP plain
ZAP_URL = "http://localhost:8081"
API_KEY = "c1vlieurbp6muvgdg378g1ehlt"

async def test_zap():
    headers = {"X-ZAP-API-Key": API_KEY}
    print(f"Testing connectivity to {ZAP_URL}...")
    
    # 1. Test Root
    try:
        async with httpx.AsyncClient() as client:
            resp = await client.get(ZAP_URL)
            print(f"Root endpoint: {resp.status_code}")
    except Exception as e:
        print(f"Root endpoint failed: {e}")

    # 2. Test Version Endpoint (JSON)
    try:
        async with httpx.AsyncClient() as client:
            resp = await client.get(f"{ZAP_URL}/JSON/core/view/version/", headers=headers)
            print(f"Version endpoint: {resp.status_code}")
            print(f"Body: {resp.text}")
    except Exception as e:
        print(f"Version endpoint failed: {e}")

if __name__ == "__main__":
    asyncio.run(test_zap())

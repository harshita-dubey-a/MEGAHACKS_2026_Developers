import socket
import ipaddress
from urllib.parse import urlparse
from fastapi import HTTPException, Security, status
from fastapi.security import APIKeyHeader
from config import settings

api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)

def is_internal_ip(host: str) -> bool:
    try:
        ip = ipaddress.ip_address(host)
        return ip.is_private or ip.is_loopback or ip.is_link_local
    except ValueError:
        # Not an IP address
        return False

def resolve_hostname(hostname: str) -> str:
    try:
        return socket.gethostbyname(hostname)
    except socket.gaierror:
        raise HTTPException(status_code=400, detail="Could not resolve hostname")

def validate_target_url(url: str):
    parsed = urlparse(url)
    if not parsed.scheme or parsed.scheme not in ("http", "https"):
        raise HTTPException(status_code=400, detail="Invalid URL scheme. Must be http or https")
    
    hostname = parsed.hostname
    if not hostname:
        raise HTTPException(status_code=400, detail="Invalid URL")
        
    # Check if hostname itself is an IP
    if is_internal_ip(hostname):
        raise HTTPException(status_code=400, detail="Scanning internal IPs is forbidden")
        
    # Resolve and check IP
    ip = resolve_hostname(hostname)
    if is_internal_ip(ip):
        raise HTTPException(status_code=400, detail="Scanning internal IPs is forbidden")
        
    return url

async def verify_api_key(api_key: str = Security(api_key_header)):
    if api_key != settings.API_KEY:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Could not validate credentials",
        )
    return api_key

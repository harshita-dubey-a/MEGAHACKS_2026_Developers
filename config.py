import os
from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    API_KEY: str = "secret-api-key"
    MAX_CONCURRENT_SCANS: int = 5
    
    # Scanner Configurations
    NUCLEI_PATH: str = "nuclei"  # Assumes binary is in PATH
    ZAP_API_URL: str = "https://localhost:8081"
    ZAP_API_KEY: str = "c1vlieurbp6muvgdg378g1ehlt"
    ACUNETIX_API_URL: str = "https://kali:3443/"
    ACUNETIX_API_KEY: str = "1986ad8c0a5b3df4d7028d5f3c06e936c95075764856f47789e14841451197eac"
    
    # MobSF Configuration
    MOBSF_API_URL: str = "http://localhost:8002"
    MOBSF_API_KEY: str = "eec4d3a6f14f3c57e73e87d7d4c530e01aabe73063953f299789056db9cb5519"
    
    # Nmap Configuration
    NMAP_PATH: str = "nmap" 
    NMAP_DEFAULT_ARGS: str = "-sV -T4"

    # Garak Configuration
    GARAK_PATH: str = "python3 -m garak"  # Command to run Garak
    GARAK_EXTRA_ARGS: str = "" # Ensure JSON output is handled by adapter

    STORAGE_FILE: str = "scans.json"

    class Config:
        env_file = ".env"

settings = Settings()
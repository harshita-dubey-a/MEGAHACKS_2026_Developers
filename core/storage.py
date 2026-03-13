import json
import logging
import os
from typing import Dict, Any
from uuid import UUID
from core.models import ScanResult
from config import settings
from datetime import datetime

logger = logging.getLogger(__name__)

class StorageEngine:
    def __init__(self, file_path: str = settings.STORAGE_FILE):
        self.file_path = file_path
        self._ensure_file()

    def _ensure_file(self):
        if not os.path.exists(self.file_path):
            with open(self.file_path, 'w') as f:
                json.dump({}, f)

    def save_scan(self, scan: ScanResult):
        try:
            data = self._load_data()
            # Serialize ScanResult
            # We need a robust serializer because ScanResult contains Enums/Dataclasses
            # Pydantic models (if used) have .dict() or .model_dump()
            # ScanResult is a Pydantic model (from core.models)
            
            data[str(scan.scan_id)] = scan.model_dump(mode='json')
            
            with open(self.file_path, 'w') as f:
                json.dump(data, f, indent=2, default=str)
        except Exception as e:
            logger.error(f"Failed to save scan {scan.scan_id}: {e}")

    def load_scan(self, scan_id: str) -> Dict[str, Any]:
        data = self._load_data()
        return data.get(str(scan_id))

    def load_all_scans(self) -> Dict[str, Any]:
        return self._load_data()

    def _load_data(self) -> Dict[str, Any]:
        try:
            if not os.path.exists(self.file_path):
                return {}
            with open(self.file_path, 'r') as f:
                return json.load(f)
        except json.JSONDecodeError:
            logger.warning("Storage file corrupted, resetting.")
            return {}
        except Exception as e:
            logger.error(f"Failed to load storage: {e}")
            return {}

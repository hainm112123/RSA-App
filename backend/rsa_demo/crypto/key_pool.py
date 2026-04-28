import threading
import time
import json
import os
from typing import Dict, List, Optional
from .rsa_core import generate_keypair, export_public_key_pem, export_private_key_pem

POOL_FILE = ".keys_pool.json"

class KeyPool:
    def __init__(self, pool_sizes: Dict[int, int] = None):
        if pool_sizes is None:
            # Default pool sizes for various bit lengths
            pool_sizes = {
                1024: 5,
                1536: 5,
                2048: 5,
                3072: 3,
                4096: 3,
                8192: 2
            }
        self.pool_sizes = pool_sizes
        
        # Pools are indexed by "bits:type" string for easy JSON serialization
        # types: "standard" (e=65537) and "random" (large e)
        self.pools: Dict[str, List[dict]] = {}
        for bits in pool_sizes:
            self.pools[f"{bits}:standard"] = []
            self.pools[f"{bits}:random"] = []
            
        self.lock = threading.Lock()
        self.running = False
        self.worker_thread: Optional[threading.Thread] = None
        
        # Load any existing keys from disk on startup
        self._load_from_disk()

    def _load_from_disk(self):
        if os.path.exists(POOL_FILE):
            try:
                with open(POOL_FILE, "r") as f:
                    data = json.load(f)
                    for key_id, keys in data.items():
                        if key_id in self.pools:
                            bits = int(key_id.split(":")[0])
                            e_type = key_id.split(":")[1]
                            max_size = self.pool_sizes[bits] if e_type == "standard" else 2
                            self.pools[key_id] = keys[:max_size]
            except Exception:
                pass

    def _save_to_disk(self):
        with self.lock:
            data = {key_id: keys for key_id, keys in self.pools.items()}
        
        try:
            with open(POOL_FILE, "w") as f:
                json.dump(data, f)
        except Exception:
            pass

    def start(self):
        if self.running:
            return
        self.running = True
        self.worker_thread = threading.Thread(target=self._worker, name="RSA-KeyPool-Worker", daemon=True)
        self.worker_thread.start()

    def stop(self):
        self.running = False

    def _worker(self):
        """Background thread that fills the pools."""
        while self.running:
            target = None
            
            with self.lock:
                for key_id, keys in self.pools.items():
                    bits, e_type = key_id.split(":")
                    bits = int(bits)
                    # For random large keys, we keep a smaller pool to save CPU/resources
                    max_size = self.pool_sizes[bits] if e_type == "standard" else 2
                    if len(keys) < max_size:
                        target = (bits, e_type)
                        break
            
            if target:
                bits, e_type = target
                try:
                    e = 65537 if e_type == "standard" else None
                    public_key, private_key = generate_keypair(bits, e=e)
                    
                    key_data = {
                        "bits": bits,
                        "e_type": e_type,
                        "public_key_pem": export_public_key_pem(public_key),
                        "private_key_pem": export_private_key_pem(private_key),
                        "public_key_n": str(public_key.n),
                        "public_key_e": str(public_key.e),
                        "private_key_n": str(private_key.n),
                        "private_key_d": str(private_key.d),
                        "private_key_p": str(private_key.p),
                        "private_key_q": str(private_key.q),
                        "private_key_e": str(private_key.e),
                    }
                    
                    key_id = f"{bits}:{e_type}"
                    with self.lock:
                        max_size = self.pool_sizes[bits] if e_type == "standard" else 2
                        if len(self.pools[key_id]) < max_size:
                            self.pools[key_id].append(key_data)
                    
                    self._save_to_disk()
                    
                except Exception:
                    time.sleep(5)
                
                time.sleep(0.5)
            else:
                time.sleep(5)

    def get_key(self, bits: int, e_type: str = "standard") -> Optional[dict]:
        """Fetch a pre-generated key from the pool if available."""
        key_id = f"{bits}:{e_type}"
        with self.lock:
            if key_id in self.pools and self.pools[key_id]:
                return self.pools[key_id].pop(0)
        return None

# Global instance to be shared across the app
key_pool = KeyPool()

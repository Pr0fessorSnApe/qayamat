"""
QAYAMAT — Secret Vault
Encrypts and stores API keys and credentials using Fernet symmetric encryption.
"""

import os
from pathlib import Path
from cryptography.fernet import Fernet, InvalidToken


class Vault:
    def __init__(self, key_file: str = "data/vault.key"):
        Path(key_file).parent.mkdir(parents=True, exist_ok=True)

        if not os.path.exists(key_file):
            key = Fernet.generate_key()
            with open(key_file, "wb") as f:
                f.write(key)
            # Restrict permissions on the key file
            os.chmod(key_file, 0o600)

        with open(key_file, "rb") as f:
            key = f.read().strip()

        self.cipher = Fernet(key)
        self._key_file = key_file

    def encrypt(self, plaintext: str) -> bytes:
        return self.cipher.encrypt(plaintext.encode("utf-8"))

    def decrypt(self, ciphertext: bytes) -> str:
        return self.cipher.decrypt(ciphertext).decode("utf-8")

    def store_secret(self, name: str, secret: str) -> None:
        """Encrypt and persist a secret to disk."""
        path = Path(f"data/{name}.enc")
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "wb") as f:
            f.write(self.encrypt(secret))

    def get_secret(self, name: str) -> str:
        """Retrieve and decrypt a stored secret. Returns empty string if not found."""
        path = Path(f"data/{name}.enc")
        if not path.exists():
            return ""
        try:
            with open(path, "rb") as f:
                return self.decrypt(f.read())
        except (InvalidToken, Exception):
            return ""

    def has_secret(self, name: str) -> bool:
        """Check whether a secret exists in the vault."""
        return Path(f"data/{name}.enc").exists()

    def delete_secret(self, name: str) -> bool:
        """Remove a secret from the vault."""
        path = Path(f"data/{name}.enc")
        if path.exists():
            path.unlink()
            return True
        return False

    def load_env_secrets(self) -> None:
        """
        Bootstrap the vault from environment variables.
        Reads variables ending in _API_KEY / _KEY and stores them.
        """
        import os

        mapping = {
            "OPENAI_API_KEY": "openai_api_key",
            "ANTHROPIC_API_KEY": "anthropic_api_key",
            "GEMINI_API_KEY": "gemini_api_key",
            "GOOGLE_API_KEY": "google_api_key",
            "GITHUB_TOKEN": "github_token",
            "SHODAN_API_KEY": "shodan_api_key",
            "CENSYS_API_KEY": "censys_api_key",
            "CENSYS_API_ID": "censys_api_id",
            "CENSYS_API_SECRET": "censys_api_secret",
            "OTX_API_KEY": "otx_api_key",
            "SECURITYTRAILS_API_KEY": "securitytrails_api_key",
            "URLSCAN_API_KEY": "urlscan_api_key",
            "VIRUSTOTAL_API_KEY": "virustotal_api_key",
        }
        # Censys: combine ID + secret into uid:secret format if both set
        censys_id = os.getenv("CENSYS_API_ID", "")
        censys_secret = os.getenv("CENSYS_API_SECRET", "")
        if censys_id and censys_secret and not os.getenv("CENSYS_API_KEY"):
            combined = f"{censys_id}:{censys_secret}"
            if not self.has_secret("censys_api_key"):
                self.store_secret("censys_api_key", combined)
        for env_var, secret_name in mapping.items():
            value = os.getenv(env_var, "")
            if value and not self.has_secret(secret_name):
                self.store_secret(secret_name, value)

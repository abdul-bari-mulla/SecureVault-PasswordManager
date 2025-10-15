"""
SecureVault v1.0: Basic Password Manager
=========================================
A simple password manager demonstrating:
- Master password authentication
- Basic encryption using Fernet
- JSON-based storage
- CRUD operations

Author: Abdul Bari Mulla
Date: 15 October 2025
"""

import os
import json
import hashlib
import getpass
from pathlib import Path
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64


class PasswordManager:
    """
    Basic password manager with encryption support.
    
    Security Features:
    - Master password hashed with SHA-256
    - Passwords encrypted with Fernet (AES-128 CBC)
    - Key derived using PBKDF2 with 100,000 iterations
    """
    
    def __init__(self, vault_file="vault.json"):
        self.vault_file = vault_file
        self.vault_data = {"master_hash": None, "salt": None, "passwords": {}}
        self.cipher = None
        self.is_authenticated = False
        
        # Load existing vault or create new
        if Path(vault_file).exists():
            self._load_vault()
    
    def _derive_key(self, master_password, salt):
        """
        Derive encryption key from master password using PBKDF2.
        
        Args:
            master_password (str): Master password
            salt (bytes): Salt for key derivation
            
        Returns:
            bytes: Derived encryption key
        """
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(master_password.encode()))
        return key
    
    def _hash_password(self, password):
        """Hash password using SHA-256."""
        return hashlib.sha256(password.encode()).hexdigest()
    
    def _load_vault(self):
        """Load vault data from JSON file."""
        try:
            with open(self.vault_file, 'r') as f:
                data = json.load(f)
                self.vault_data = data
        except Exception as e:
            print(f"[ERROR] Failed to load vault: {e}")
    
    def _save_vault(self):
        """Save vault data to JSON file."""
        try:
            with open(self.vault_file, 'w') as f:
                json.dump(self.vault_data, f, indent=4)
            print("[SUCCESS] Vault saved securely.")
        except Exception as e:
            print(f"[ERROR] Failed to save vault: {e}")
    
    def setup_master_password(self):
        """
        Initialize vault with a new master password.
        """
        if self.vault_data["master_hash"]:
            print("[ERROR] Master password already set!")
            return False
        
        print("\n=== Master Password Setup ===")
        master_pass = getpass.getpass("Create master password: ")
        confirm_pass = getpass.getpass("Confirm master password: ")
        
        if master_pass != confirm_pass:
            print("[ERROR] Passwords do not match!")
            return False
        
        if len(master_pass) < 8:
            print("[ERROR] Master password must be at least 8 characters!")
            return False
        
        # Generate salt and hash master password
        salt = os.urandom(16)
        self.vault_data["salt"] = base64.b64encode(salt).decode()
        self.vault_data["master_hash"] = self._hash_password(master_pass)
        
        # Initialize cipher
        key = self._derive_key(master_pass, salt)
        self.cipher = Fernet(key)
        self.is_authenticated = True
        
        self._save_vault()
        print("[SUCCESS] Master password created!")
        return True
    
    def authenticate(self):
        """
        Authenticate user with master password.
        """
        if not self.vault_data["master_hash"]:
            print("[ERROR] No master password set. Run setup first.")
            return False
        
        print("\n=== Authentication ===")
        master_pass = getpass.getpass("Enter master password: ")
        
        if self._hash_password(master_pass) != self.vault_data["master_hash"]:
            print("[ERROR] Incorrect master password!")
            return False
        
        # Initialize cipher
        salt = base64.b64decode(self.vault_data["salt"])
        key = self._derive_key(master_pass, salt)
        self.cipher = Fernet(key)
        self.is_authenticated = True
        
        print("[SUCCESS] Authentication successful!")
        return True
    
    def add_password(self, service, username, password):
        """
        Add a new password entry.
        
        Args:
            service (str): Service name (e.g., 'gmail', 'github')
            username (str): Username/email
            password (str): Password to store
        """
        if not self.is_authenticated:
            print("[ERROR] Not authenticated!")
            return False
        
        # Encrypt password
        encrypted_password = self.cipher.encrypt(password.encode()).decode()
        
        # Store entry
        self.vault_data["passwords"][service] = {
            "username": username,
            "password": encrypted_password
        }
        
        self._save_vault()
        print(f"[SUCCESS] Password for '{service}' added!")
        return True
    
    def get_password(self, service):
        """
        Retrieve and decrypt password for a service.
        
        Args:
            service (str): Service name
            
        Returns:
            dict: Dictionary with username and decrypted password
        """
        if not self.is_authenticated:
            print("[ERROR] Not authenticated!")
            return None
        
        if service not in self.vault_data["passwords"]:
            print(f"[ERROR] No password found for '{service}'")
            return None
        
        entry = self.vault_data["passwords"][service]
        decrypted_password = self.cipher.decrypt(entry["password"].encode()).decode()
        
        return {
            "username": entry["username"],
            "password": decrypted_password
        }
    
    def list_services(self):
        """List all stored services."""
        if not self.is_authenticated:
            print("[ERROR] Not authenticated!")
            return
        
        services = list(self.vault_data["passwords"].keys())
        if not services:
            print("[INFO] No passwords stored yet.")
            return
        
        print("\n=== Stored Services ===")
        for idx, service in enumerate(services, 1):
            username = self.vault_data["passwords"][service]["username"]
            print(f"{idx}. {service} ({username})")
    
    def delete_password(self, service):
        """Delete a password entry."""
        if not self.is_authenticated:
            print("[ERROR] Not authenticated!")
            return False
        
        if service in self.vault_data["passwords"]:
            del self.vault_data["passwords"][service]
            self._save_vault()
            print(f"[SUCCESS] Password for '{service}' deleted!")
            return True
        else:
            print(f"[ERROR] No password found for '{service}'")
            return False


def main():
    """Main CLI interface."""
    pm = PasswordManager()
    
    # Check if first time setup needed
    if not Path("vault.json").exists() or not pm.vault_data["master_hash"]:
        print("Welcome to SecureVault Password Manager!")
        pm.setup_master_password()
    else:
        pm.authenticate()
    
    if not pm.is_authenticated:
        return
    
    # Main menu loop
    while True:
        print("\n" + "="*40)
        print("SecureVault Password Manager v1.0")
        print("="*40)
        print("1. Add Password")
        print("2. Get Password")
        print("3. List Services")
        print("4. Delete Password")
        print("5. Exit")
        print("="*40)
        
        choice = input("Select option: ").strip()
        
        if choice == "1":
            service = input("Service name: ").strip()
            username = input("Username: ").strip()
            password = getpass.getpass("Password: ")
            pm.add_password(service, username, password)
        
        elif choice == "2":
            service = input("Service name: ").strip()
            result = pm.get_password(service)
            if result:
                print(f"\nUsername: {result['username']}")
                print(f"Password: {result['password']}")
        
        elif choice == "3":
            pm.list_services()
        
        elif choice == "4":
            service = input("Service name: ").strip()
            pm.delete_password(service)
        
        elif choice == "5":
            print("Goodbye!")
            break
        
        else:
            print("[ERROR] Invalid option!")


if __name__ == "__main__":
    main()

# SecureVault Password Manager

A secure, CLI-based password manager built with Python demonstrating cryptographic best practices for cybersecurity professionals.

## 🎯 Project Purpose

This project is part of my cybersecurity learning journey as a final-year computer engineering student. It demonstrates:

- Practical application of cryptography
- Secure coding practices
- Progressive software development
- Security-first design principles

## 🔐 Current Features (v1.0)

- **Master Password Protection**: SHA-256 hashed master password
- **Strong Encryption**: AES-128 CBC via Fernet
- **Key Derivation**: PBKDF2-HMAC-SHA256 (100,000 iterations)
- **Persistent Storage**: Encrypted JSON vault
- **Basic Operations**: Add, retrieve, list, and delete passwords

## 🛡️ Security Architecture

### Encryption Flow

1. User creates master password
2. System generates random 16-byte salt
3. PBKDF2 derives 256-bit key from master password + salt
4. Fernet cipher encrypts/decrypts individual passwords
5. Master password hash stored (SHA-256)

### What's Protected

- All passwords encrypted at rest
- Master password never stored in plain text
- Salt ensures unique key derivation per vault

### Current Limitations

- Master password uses SHA-256 (will upgrade to Argon2)
- No password strength validation
- No breach detection
- No session timeout

## 🚀 Installation

Clone repository
git clone https://github.com/abdul-bari-mulla/SecureVault-PasswordManager.git
cd SecureVault-PasswordManager

Create virtual environment
python -m venv venv
source venv/bin/activate # Windows: venv\Scripts\activate

Install dependencies
pip install -r requirements.txt

Run
python src/password_manager.py

## 📖 Usage

### First time setup
```bash
$ python src/password_manager.py
```
Welcome to SecureVault Password Manager!
Create master password: *\*\*\*

### Add password
Add Password
Service name: github
Username: your_username
Password: *\*\*\*

### Retrieve password
Get Password
Service name: github
Username: your_username
Password: your_github_password

## 🔄 Development Roadmap

- [x] **v1.0**: Basic encryption and storage
- [ ] **v1.1**: Argon2 password hashing
- [ ] **v1.2**: Password generation and strength validation
- [ ] **v1.3**: Have I Been Pwned breach detection
- [ ] **v1.4**: Session timeout and clipboard support
- [ ] **v2.0**: Password audit, 2FA, and export features

## 🧪 Testing

Run tests (coming in v1.3)
pytest tests/

## 📝 License

MIT License - See LICENSE file

## 👤 Author

Abdul Bari Mulla - Aspiring Cybersecurity Professional  
[ [GitHub](https://github.com/abdul-bari-mulla) | [LinkedIn](https://www.linkedin.com/in/abdul-bari-mulla/) | mullaabdulbari10@gmail.com

---

**⚠️ Disclaimer**: This is an educational project. For production use, consider established password managers like Bitwarden or 1Password.

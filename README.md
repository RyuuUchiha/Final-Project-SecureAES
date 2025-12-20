🔐 SecureAES – File Encryption & Decryption Tool

📌 Project Title

SecureAES – AES-256 File Encryption & Decryption Application

📖 Short Description

SecureAES is a Python-based tool that allows users to securely encrypt and decrypt files using AES-256 encryption. It uses a password to generate a strong encryption key, ensuring that only authorized users can access the content. The tool features a user-friendly GUI and performs all encryption locally, keeping files safe and private without uploading them to any server.

The application allows users to:

Encrypt and decrypt multiple files

Choose output locations

Securely delete original or encrypted files

Monitor progress and logs during batch operations

⚙️ Installation / Setup Instructions
1️⃣ Prerequisites

Python 3.11 or later

Windows / Linux / macOS

2️⃣ Clone the Repository
git clone https://github.com/your-username/SecureAES.git
cd SecureAES

3️⃣ Create Virtual Environment (Recommended)
python -m venv venv
venv\Scripts\activate      # Windows
source venv/bin/activate   # Linux / macOS

4️⃣ Install Dependencies
pip install -r requirements.txt

5️⃣ Run the Application
python main.py

▶️ Usage Guide
🔐 Encrypt Files

- Open SecureAES

- Go to Encryption Tab

- Click Add Files

- Enter a strong password

- (Optional) Enable Delete original files

- Click Encrypt

- Select output folder

- View progress and logs

🔓 Decrypt Files

- Go to Decryption Tab

- Add .enc files

- Enter the correct password

- (Optional) Enable Delete encrypted files

- Click Decrypt

- View output and logs

📦 Dependencies / Libraries Used

cryptography – AES-256-GCM encryption

argon2-cffi – Argon2 key derivation

tkinter – GUI framework

customtkinter – Modern UI styling

Pillow (PIL) – Image handling

psutil – System memory checks
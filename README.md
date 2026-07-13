<<<<<<< HEAD
# PhantomShield AI

AI-powered cybersecurity platform for detecting **phishing URLs**, **malicious QR codes**, and **scam text messages**.

## Features

| Module | Description |
|--------|-------------|
| **URL Scanner** | Ensemble ML (RandomForest + GradientBoosting) + heuristic rules + optional VirusTotal |
| **QR Scanner** | Multi-pass image preprocessing, hidden URL detection, UPI/WiFi QR support |
| **Text Scam Scanner** | Keyword analysis + embedded URL scanning |
| **Cyber Assistant** | Groq LLM-powered security Q&A |
| **Dashboard** | Live scan history, threat analytics, system status |

## Prerequisites

- **Python 3.9+**
- **Windows**: [ZBar](https://sourceforge.net/projects/zbar/files/) for QR decoding (install and add to PATH)
- Optional: [Groq API key](https://console.groq.com/) for chat assistant
- Optional: [VirusTotal API key](https://www.virustotal.com/) for URL reputation

## Quick Start (Windows)

```bat
cd "D:\PhantomShield AI"
start.bat
```

This will:
1. Create a virtual environment (`.venv`)
2. Install all dependencies
3. Start the **Flask backend** on `http://localhost:5000`
4. Start the **Streamlit frontend** on `http://localhost:8501`

## Manual Setup

### 1. Create virtual environment

```powershell
cd "D:\PhantomShield AI"
python -m venv .venv
.\.venv\Scripts\activate
```

### 2. Install dependencies

```powershell
pip install -r backend\requirements.txt
pip install -r frontend\requirements.txt
```

### 3. Configure API keys

```powershell
copy .env.example backend\.env
# Edit backend\.env and add your keys
```

### 4. Train the URL ML model (recommended)

```powershell
cd backend\ai_engines
python train_url_model.py
cd ..\..
```

This downloads the Kaggle phishing dataset and trains an ensemble classifier (~2-5 minutes).

### 5. Start the backend (Terminal 1)

```powershell
cd backend
python app.py
```

### 6. Start the frontend (Terminal 2)

```powershell
cd frontend
streamlit run app.py
```

Open **http://localhost:8501** in your browser.

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/health` | System status (ML model, API keys) |
| POST | `/api/scan/url` | Scan a single URL |
| POST | `/api/scan/url/batch` | Scan up to 20 URLs |
| POST | `/api/scan/qr` | Upload QR image (multipart) |
| POST | `/api/scan/text` | Analyze scam text |
| GET | `/api/scan/history` | Recent scan history |
| POST | `/api/chat/ask` | Cyber assistant chat |

## Project Structure

```
PhantomShield AI/
├── start.bat                 # One-click launcher
├── backend/
│   ├── app.py                # Flask entry point
│   ├── config.py             # Configuration
│   ├── ai_engines/
│   │   ├── url_analyzer.py   # URL detection engine
│   │   ├── qr_analyzer.py    # QR decode + analysis
│   │   ├── nlp_analyzer.py   # Text scam detection
│   │   ├── threat_intel.py   # VirusTotal integration
│   │   └── train_url_model.py
│   └── routes/
├── frontend/
│   ├── app.py                # Streamlit home
│   └── pages/                # Scanner pages
```

## Troubleshooting

| Issue | Fix |
|-------|-----|
| QR scan fails on Windows | Install ZBar and add to PATH |
| Backend connection error | Ensure Flask is running on port 5000 |
| Chat assistant offline | Set `GROQ_API_KEY` in `backend/.env` |
| Low URL accuracy | Run `train_url_model.py` to generate the ML model |
| VirusTotal not working | Set `VIRUSTOTAL_API_KEY` in `backend/.env` |

## License

MIT — For educational and personal use.
=======
# PhantomShield-AI
>>>>>>> 77c568d119b81fd173f01d5ab3b9923ab7e1d186

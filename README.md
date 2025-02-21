# 🚀 Log Analysis & Threat Detection System

## 📌 Project Overview
The **Log Analysis & Threat Detection System** is a powerful tool designed to analyze system logs, detect security threats, and identify anomalies using **Machine Learning and Trie-based detection**. The project integrates **FastAPI** for backend processing and an **HTML-based frontend** for user interaction.

---

## 🛠️ Features
✅ **Real-time Log Analysis** – Detects security threats & anomalies from logs.
✅ **Machine Learning Integration** – Uses **TF-IDF + Random Forest** for anomaly detection.
✅ **Trie-Based Threat Detection** – Quickly identifies predefined threat patterns.
✅ **User-Friendly Web Interface** – Upload log files or manually enter logs for analysis.
✅ **FastAPI Backend** – High-performance backend with API endpoints.
✅ **Secure & Scalable** – Can be extended for corporate-level threat monitoring.

---

## 🏗️ Project Structure
```
Log-Analysis-Threat-Detection-System/
├── main.py                 # FastAPI backend
├── app.py                  # Streamlit (Optional if using HTML frontend)
├── log_parser.py           # Parses log files
├── threat_detector.py      # Detects security threats using Trie
├── anomaly_detector.py     # Uses ML to find anomalies
├── templates/              # HTML frontend
│   ├── index.html          # Main web interface
├── logs/                   # Folder for storing sample log files
├── models/                 # Folder for storing trained ML models
├── static/                 # Static assets (CSS, JS)
├── requirements.txt        # List of dependencies
├── README.md               # Project Documentation
```

---

## 🎯 Installation & Setup

### 🔹 Step 1: Clone the Repository
```sh
git clone https://github.com/BhupendraMewada/Log-Analysis-Threat-Detection-System.git
cd Log-Analysis-Threat-Detection-System
```

### 🔹 Step 2: Create a Virtual Environment
```sh
python -m venv myenv
source myenv/bin/activate  # On Windows: myenv\Scripts\activate
```

### 🔹 Step 3: Install Dependencies
```sh
pip install -r requirements.txt
```

### 🔹 Step 4: Start FastAPI Backend
```sh
uvicorn main:app --reload --host 127.0.0.1 --port 8080
```

### 🔹 Step 5: Open the Web Interface
➡️ **Go to:** `http://127.0.0.1:8080/`

---

## 📡 API Endpoints
### **1️⃣ Analyze a Single Log**
```http
POST /analyze-log/
```
**Request:**
```json
{ "log": "User attempted SQL Injection" }
```
**Response:**
```json
{ "log": "User attempted SQL Injection", "threat_detected": true, "anomaly_detected": false }
```

### **2️⃣ Upload a Log File**
```http
POST /upload-logfile/
```
**Response:**
```json
{ "filename": "sample.log", "results": [...] }
```

---

## 📝 Sample Log Data
**Example Log File (`logs/sample.log`)**
```
[2025-02-21 09:00:12] INFO - System: Windows Update completed successfully.
[2025-02-21 12:30:50] ERROR - Security: Unauthorized USB device detected.
[2025-02-21 13:10:30] ERROR - Network: Suspicious outbound traffic detected.
```

---

## 🔥 Future Enhancements
🚀 **Add AI-based anomaly detection using deep learning.**
🚀 **Improve UI with interactive charts and logs filtering.**
🚀 **Deploy the system on cloud platforms (AWS, Azure, etc.).**

---

## 🤝 Contributing
💡 Pull requests are welcome! Feel free to fork the repo, make improvements, and submit a PR.

---

## 📜 License
📝 This project is **open-source** and available under the **MIT License**.

---

## 📬 Contact
👤 **Bhupendra Mewada**  
📧 **[Email](mailto:your-email@example.com)**  
🔗 **[LinkedIn](https://www.linkedin.com/in/bhupendramewada/)**  
📂 **[GitHub](https://github.com/BhupendraMewada/)**

---

🌟 **If you like this project, consider giving it a star on GitHub!** ⭐


# 🔐 Vuln_Finder – Web Vulnerability Scanner

## 📌 Overview

**Vuln_Finder** is a cybersecurity tool designed to detect vulnerabilities in web applications. It provides both **basic web scanning (via browser)** and **advanced deep scanning (via desktop application)**.

This project is developed as a **Final Year Project** focusing on **Web Security, Penetration Testing, and Vulnerability Analysis**.

---

## 🚀 Features

### 🌐 Web-Based Scanner

* Quick vulnerability scan
* URL-based scanning
* Detects:

  * SQL Injection
  * XSS (Cross-Site Scripting)
  * Open Ports (basic)
* User-friendly interface

### 💻 Desktop Application (Advanced Scanner)

* Full deep scan
* Automatic vulnerability detection
* Manual testing options
* Detailed reports
* Integration with scanning tools

---

## 🛠️ Technologies Used

### Frontend

* React.js / Next.js
* Tailwind CSS

### Backend

* .NET (C#)
* REST APIs

### Desktop Application

* .NET (WPF / WinForms)

### Security Tools Integration

* Nmap
* OpenVAS
* Custom scanning scripts

---

## 📂 Project Structure

```
Vuln_Finder/
│
├── Vuln_Finder/                # Web frontend
├── WebVulnScanner.Core/       # Core scanning logic
├── WebVulnScanner.Desktop/    # Desktop application
├── OPENVAS_SETUP_GUIDE.txt    # Setup instructions
├── WebVulnScanner.sln         # Solution file
```

---

## ⚙️ Installation & Setup

### 1️⃣ Clone the Repository

```bash
git clone https://github.com/your-username/Vuln_Finder.git
cd Vuln_Finder
```

### 2️⃣ Backend Setup (.NET)

```bash
cd WebVulnScanner.Core
dotnet build
dotnet run
```

### 3️⃣ Frontend Setup

```bash
cd Vuln_Finder
npm install
npm run dev
```

### 4️⃣ Desktop Application

* Open `WebVulnScanner.sln` in Visual Studio
* Build and Run the project

---

## 🧪 Usage

### Web Scanner

1. Enter target URL
2. Click "Scan"
3. View vulnerabilities

### Desktop Scanner

1. Install the application
2. Select scan type:

   * Basic Scan
   * Deep Scan
3. Generate report

---

## 📊 Sample Output

* Vulnerability Name
* Severity Level
* Description
* Recommended Fix

---

## 🎯 Project Goals

* Provide easy vulnerability detection
* Help beginners in cybersecurity
* Combine web + desktop scanning
* Create BurpSuite-like lightweight tool

---

## 🔮 Future Enhancements

* AI-based vulnerability detection
* Real-time monitoring
* Browser proxy integration (like BurpSuite)
* Automated patch suggestions

---

## 👨‍💻 Author

**Sasidharan M**
MSc Computer Science

---

## ⚠️ Disclaimer

This tool is developed for **educational purposes only**.
Do not use it on unauthorized systems.

---

## ⭐ Support

If you like this project:

* ⭐ Star the repository
* 🍴 Fork it
* 📢 Share it

---



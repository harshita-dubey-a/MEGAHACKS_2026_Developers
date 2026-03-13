# 🛡️ Advanced Intelligent Infrastructre Vulnerability Scanner

<!-- BADGES -->
![Security](https://img.shields.io/badge/Security-DAST-critical)
![OWASP](https://img.shields.io/badge/OWASP-Beyond%20Top%2010-important)
![Platform](https://img.shields.io/badge/Platform-Web%20%7C%20Mobile-blue)
![API](https://img.shields.io/badge/Architecture-Single%20Unified%20API-success)
![SOC](https://img.shields.io/badge/SOC-Ready-orange)
![Status](https://img.shields.io/badge/Status-Industry%20Grade-brightgreen)

---

## 📌 Overview

An **intelligent, automated vulnerability scanning platform** built for **modern web applications, APIs, and authenticated environments**.  
It performs **advanced Dynamic Application Security Testing (DAST)** using smart crawling, deep request–response analysis, and exploit validation.

This platform goes **far beyond OWASP Top 10**, delivering **enterprise-grade security testing** while remaining scalable, reliable, and SOC-ready.

---

## 🚀 Key Features

- 🔍 Advanced **DAST engine** with smart crawling
- 🔐 Full **authenticated scanning** (JWT, cookies, headers)
- 🧠 Deep **request–response correlation**
- 📊 Severity, exploitability & confidence-based findings
- 📱 **Web App + Mobile App powered by a single API**
- 🔗 Easy integration with **SOC, SIEM & analyst portals**
- ⚙️ Reliable, scalable & production-ready architecture

---

## 🔐 Vulnerability Coverage (Beyond OWASP Top 10)

### 🧩 Application & API Vulnerabilities

- OWASP Top 10 (A01–A10)
- **SQL Injection (SQLi)**
- **Cross-Site Scripting (XSS)** – Reflected, Stored, DOM
- **Server-Side Template Injection (SSTI)**
- **Client-Side Template Injection (CSTI)**
- **Server-Side Request Forgery (SSRF)**
- **Remote Code Execution (RCE)**
- **Local File Inclusion (LFI)**
- Command Injection
- Insecure Deserialization

### 🔑 Authorization & Access Control

- **Broken Access Control (BAC)**
- **Broken Object Level Authorization (BOLA)**
- IDOR
- Privilege Escalation
- Role-based authorization flaws

### 🌐 Advanced Detection

- **OAST / Out-of-Band interaction testing**
- Authentication bypass
- Business logic flaws
- Sensitive data exposure

---

## 🧠 Intelligent Scanning Engine

- Context-aware fuzzing
- Adaptive payload injection
- Authenticated crawling
- Automatic endpoint discovery
- API schema & parameter analysis
- Deep diff-based response comparison

> ⚠️ False positives are actively minimized using exploit validation and behavioral analysis.

---

## 📊 Vulnerability Classification

Each vulnerability includes:

- **Severity**: Critical | High | Medium | Low | Info
- **Exploitability Score**
- **Confidence Level** (Confirmed / Probable / Potential)

This allows SOC teams and developers to **prioritize real risks efficiently**.

---

## 🧾 Reports & Remediation

- Developer-friendly vulnerability reports
- Proof-of-Concept (PoC)
- Clear remediation guidance
- Risk-based prioritization
- Exportable audit-ready reports

---

# 🖥️ Web Application

The web dashboard provides **full control over the scanning lifecycle**.

### Web Capabilities

- Real-time dashboard
- Add & manage targets
- Authenticated scans
- Scan history & analytics
- Vulnerability management
- Role-based access control
- Report generation
- Account & system settings

---

## 📸 Web Application Screenshots

### Main API – Running Logs
![Main API Logs](https://github.com/user-attachments/assets/34e51ffc-1365-47a5-8e34-19b28c91c707)

### Dashboard
![Dashboard](https://github.com/user-attachments/assets/60a18323-d86f-4cd2-be24-0a884b288990)

### Add Target Page
![Add Target](https://github.com/user-attachments/assets/cab16c5e-2de9-4a2b-bf25-135110eadfda)

### Scans Overview
![Scans](https://github.com/user-attachments/assets/477b66fe-f760-4c8e-b263-af4d0e6d6e19)

### Vulnerabilities Listing
![Vulnerabilities](https://github.com/user-attachments/assets/fa5947dd-8975-41fa-8b3c-6d5cc72b6005)

### Reports Generation
![Reports](https://github.com/user-attachments/assets/b48c35c8-6bdf-4875-a2dd-fb77773e49bb)

### User & Role Management
![User Management](https://github.com/user-attachments/assets/c3d0460c-9df2-4aee-b84f-f7044c38f69e)

### Account Settings
![Account Settings](https://github.com/user-attachments/assets/f2dbdce5-8abb-4664-ad33-e65a08e57232)

---

# 📱 Mobile Application

The mobile app enables **full system monitoring and control directly from a smartphone**, without running the entire platform.

### Mobile Capabilities

- Initiate scans
- Monitor scan progress
- View vulnerabilities
- Manage targets
- **LLM-powered chatbot for scan queries**
- Complete system visibility

---

## 📸 Mobile Application Screenshots

### Mobile Dashboard
![Mobile Dashboard](https://github.com/user-attachments/assets/e07b8d1e-e65e-4742-9c77-f22aa402421b)

### All Vulnerabilities
![All Vulnerabilities](https://github.com/user-attachments/assets/f3798c64-9e6b-4e3e-ba58-032e7cf476fe)

### LLM Chatbot
![LLM Chatbot](https://github.com/user-attachments/assets/30e7e1ba-10ff-45aa-92ec-c4bf62fb6c88)

### Scan Screen
![Scan Screen](https://github.com/user-attachments/assets/e6128c8f-5777-455d-8cf3-7a13754bef46)

### Add Target
![Add Target](https://github.com/user-attachments/assets/c7f91bbd-fbdd-4e1f-80c8-367fb58e8f1e)

### Main Control Screen
![Main Screen](https://github.com/user-attachments/assets/ca4543b2-ec69-41a1-9463-a281fcfa75d0)

---

## 🔗 Unified API Architecture

Both Web App and Mobile App run on a **single centralized API**.

```text
Web App  ─┐
          ├── Central Vulnerability Scanning API
Mobile App┘

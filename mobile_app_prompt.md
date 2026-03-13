# Flutter DAST Orchestrator Mobile App Prompt

**Role:** You are a Senior Flutter Developer and UI/UX Designer specializing in Cybersecurity Tools.

**Goal:** Create a complete, production-grade Flutter application that serves as the mobile control center for a **Unified Risk Management Platform (DAST Orchestrator)**. The app must run on Android and iOS.

## 1. Design Aesthetic & Theme (Cyberpunk/Professional)
The user requires a look that says "Advanced Security Tool" but remains usable and professional.
- **Theme:** Dark Mode by default.
- **Primary Color:** Neon Red (`#FF1744`) or Cyberpunk Blue (`#00E5FF`).
- **Background:** Deep gray/black (`#121212`) with subtle hex-grid or circuit board patterns (optional SVG overlay).
- **Typography:** Monospace fonts for logs (e.g., `JetBrains Mono`, `Google Fonts: Roboto Mono`) and clean Sans-Serif (e.g., `Inter`, `Outfit`) for UI elements.
- **UI Elements:**
    - **Glassmorphism:** Use semi-transparent cards with blurs for scan cards.
    - **Animations:** Subtle pulses on "Scanning" status indicators.
    - **Charts:** Donut charts for vulnerability severity breakdown.

## 2. Core Features & Screens

### A. Dashboard (Home)
- **Header:** "Security Overview" with a connection status indicator (pinging `/health`).
- **Summary Cards:** 
    - Total Vulnerabilities (Big number).
    - Grid of severity counts (Critical [Red], High [Orange], Medium [Yellow], Low [Blue]).
    - Use `GET /api/v1/dashboard/summary` to populate this.
- **Recent Activity:** A horizontal list of the last 5 scans with their status badges (Running, Completed, Failed).

### B. New Scan (Launcher)
- **Input Form:**
    - **Target:** Text field (URL, IP, or Model Name).
    - **Scan Type:** Dropdown/Chips: `Web` (Acunetix), `Mobile` (MobSF), `Network` (Nmap), `LLM` (Garak).
    - **Asset Context:** (Hidden/Auto-derived or Optional).
    - **Options:** "Deep Scan", "Simple Scan" (mapped to internal profiles).
- **Action:** Large "START SCAN" button (sends `POST /api/v1/scan`).
- **Mobile Specific:** If Type = Mobile, allow picking an APK file (Multi-part upload). *Note: Backend supports file path currently, assume file upload support will be added or use URL for now.*

### C. Scan Detail View (Real-time)
- **Header:** Target URL + Dynamic Status Badge.
- **Tabs:**
    1.  **Overview:** Donut chart of findings.
    2.  **Findings:** List of vulnerabilities found so far.
        - Each item shows: Severity Icon, Name, and Risk Score.
        - Click to expand details (Description, Solution, CVD/CWE).
        - Use `GET /api/v1/scan/{id}/findings`.
    3.  **Console:** Live TTY-style log output.
        - Use `GET /api/v1/scan/{id}/logs`.
        - Auto-scroll to bottom.
        - Green text on black background.

### D. Settings
- **API Configuration:** Input field for Backend URL (e.g., `http://10.0.2.2:8060`) and API Key.
- **Theme Toggle:** (Cyberpunk / Corporate).

## 3. Technical Requirements & Architecture
- **State Management:** Use `Riverpod` or `Bloc` for robust state handling.
- **Networking:** Use `Dio` for HTTP requests with an Interceptor for the API Key (`X-API-Key`).
- **Models:** Create strict Dart models matching the Python Pydantic models:
    ```dart
    enum ScanType { web, mobile, network, llm }
    enum Severity { critical, high, medium, low, info }
    
    class ScanRequest {
      final ScanType type;
      final String target;
      // ...
    }
    ```
- **Charts:** Use `fl_chart`.
- **Markdown:** Use `flutter_markdown` for rendering vulnerability descriptions.

## 4. API Endpoints Reference
Base URL: `http://<backend_ip>:8060/api/v1`

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `POST` | `/scan` | Start a scan. Body: `{ "type": "web", "target": "..." }` |
| `GET` | `/dashboard/summary` | Dashboard stats. |
| `GET` | `/dashboard/scans` | List of recent scans. |
| `GET` | `/scan/{id}` | Scan status and summary. |
| `GET` | `/scan/{id}/findings` | List of finding objects. |
| `GET` | `/scan/{id}/logs` | List of string logs. |

## 5. Implementation Steps for You (The AI)
1.  **Initialize Project:** `flutter create dast_app`.
2.  **Add Dependencies:** `dio`, `flutter_riverpod`, `fl_chart`, `google_fonts`, `flutter_markdown`.
3.  **Setup Theme:** Define the dark theme data.
4.  **Create API Client:** Service class to handle Dio requests.
5.  **Build UI:**
    - `DashboardScreen`
    - `ScanFormScreen`
    - `ScanResultScreen`
6.  **Connect State:** Wire up the UI to the providers.

**Prompt End:** Please generate the `pubspec.yaml`, `main.dart`, and the core `api_service.dart` to get started.

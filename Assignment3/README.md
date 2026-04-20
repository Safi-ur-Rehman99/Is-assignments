# Assignment 3 - Network Security Scanner & Firewall Visualizer

This assignment is implemented as a web-based tool using **Flask (Python backend)** with a single HTML frontend.

## What has been implemented

### 1. User Interface (Frontend)

- Input field for target IP/hostname.
- Dropdown for scan type:
  - TCP SYN
  - UDP
  - Full Connect
- Port range input (supports values like `1-1024`, `80,443`, `20-25,80`).
- Start Scan button.
- Result table showing:
  - IP
  - Port
  - Protocol
  - Service
  - Status
- Firewall rule creation form:
  - Action (ALLOW / DENY)
  - IP/CIDR/any
  - Port/range/any
  - Protocol (ANY/TCP/UDP)
  - Priority
- Rule table with delete action.
- Traffic flow visualization section showing allowed/blocked decisions and matched rules.

### 2. Scanning Engine (Backend)

- Uses `python-nmap` with scan modes:
  - `-sS` for TCP SYN
  - `-sU` for UDP
  - `-sT` for Full Connect
- Supports custom port ranges.
- Parses Nmap output into structured scan results.
- Includes service name detection and scan status handling.
- Includes a fallback TCP full-connect scanner (socket-based) if Nmap is not available.

### 3. Firewall Simulation Logic

- Supports rule chaining with priority-based evaluation (lowest priority first).
- Supports matching by:
  - IP (exact, CIDR, or `any`)
  - Port (exact, range, or `any`)
  - Protocol (`TCP`, `UDP`, `ANY`)
- First matching rule determines traffic decision.
- Default behavior for unmatched traffic: **ALLOW**.
- Returns summary counts for allowed vs blocked flows.

### 4. Extra Security Insight

- Adds a "possible vulnerabilities" list based on exposed high-risk open ports (heuristic warnings).

## Files in Assignment3

- `app.py` - Flask backend (scan APIs + firewall simulation APIs).
- `templates/index.html` - Complete frontend UI, styling, and client logic.
- `requirements.txt` - Python dependencies.
- `README.md` - This documentation.

## How to run

1. Open terminal in `Assignment3`.
2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
3. Ensure **Nmap** is installed on your machine (recommended for full scan support).
4. Start the Flask app:
   ```bash
   python app.py
   ```
5. Open browser:
   - `http://127.0.0.1:5000`

## Notes

- If Nmap is missing:
  - Full Connect scans can still run via socket fallback.
  - TCP SYN and UDP scans require Nmap.
- This is a simulation/educational tool and should only be used on systems/networks you are authorized to test.

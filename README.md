# AI-Powered Web Vulnerability Scanner

A Linux GUI application that runs Nmap and Gobuster scans, using an AI model to predict vulnerabilities and CVSS scores based on the results.

## Development Setup (For Contributors)

### 1. Prerequisites
Ensure you have the following installed on your Kali Linux system:
- **Python 3.9+**
- **Nmap**: `sudo apt update && sudo apt install nmap`
- **Gobuster**: `sudo apt install gobuster`
- **Nikto**: `sudo apt install nikto`
- **Git**: `sudo apt install git`

### 2. Clone the Repository
```bash
git clone <your-github-repo-url>
cd Ai-Vuln-Scanner
```

### 3. Set Up Python Virtual Environment
```bash
# Create the virtual environment
python3 -m venv venv

# Activate the environment
source venv/bin/activate

# Install required Python packages
pip install -r requirements.txt
```

### 4. How to Collect Scan Data for the AI Model

We are in the data collection phase. Please use the provided engine to scan targets and generate labeled data.

#### Basic Usage:
1. **Activate the virtual environment:** `source venv/bin/activate`
2. **Run the data collection engine:** `python3 main.py`
3. **Enter the target IP** when prompted (e.g., `192.168.56.102` for a Metasploitable VM).
4. The script will run Nmap and Gobuster, then save a features file (`data/<target>_features.json`).

**Note:** Nikto scans can be slow (15-30 minutes per target). Please be patient. This provides crucial data for the AI model.

#### Auto-Labeling Your Scan:
After scanning a **known vulnerable target** (like Metasploitable), run the labeler script:
```bash
python3 utils/labeler.py data/192.168.56.102_features.json
```
This will create a `data/labeled_192.168.56.102.json` file with both features and correct labels.

### 5. What to Scan
- **Vulnerable VMs:** Metasploitable 2/3, OWASP Juice Shop, VulnHub machines.
- **Clean Systems:** Modern Ubuntu servers, basic WordPress sites (to teach the model what "normal" looks like).
- **Labeling:** For vulnerable VMs, use the `labeler.py` script. For clean systems, you will need to manually create the `labeled_*.json` file setting all `vuln_*` values to `0` and `cvss_score` to a low value.

### 6. Sharing Your Data
**Please only commit and push the `labeled_*.json` files** to the repository. Do not commit the raw `_nmap.xml`, `_gobuster.txt`, or `_features.json` files, as they are ignored by git.

### Folder Structure
```
Ai-Vuln-Scanner/
├── data/               # Scan data (only labeled_*.json should be committed)
├── src/                # Source code (nmap_parser.py, gobuster_parser.py)
├── utils/              # Utilities (labeler.py)
├── main.py             # Main data collection script
├── requirements.txt    # Python dependencies
└── README.md           # This file
```

## Current Capabilities
- ✅ Runs Nmap scans with version detection
- ✅ Runs Gobuster directory scans
- ✅ Parses results into a structured JSON feature vector
- ✅ Auto-labels scans for known vulnerable targets

## Next Steps
1. Collect a large dataset of `labeled_*.json` files.
2. Build the AI model to train on this data.
3. Develop the PyQt5 GUI interface.
4. Integrate the model into the GUI for predictions.

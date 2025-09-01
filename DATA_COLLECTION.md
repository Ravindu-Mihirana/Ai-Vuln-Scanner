# Data Collection Protocol

## Folder Structure in `data/`:
- `labeled_*.json`: ✅ **DO COMMIT** - Final training data with features + labels
- `*_features.json`: ❌ **DO NOT COMMIT** - Intermediate feature files
- `*_nmap.xml`: ❌ **DO NOT COMMIT** - Raw scan data
- `*_gobuster.txt`: ❌ **DO NOT COMMIT** - Raw scan data  
- `*_nikto.txt`: ❌ **DO NOT COMMIT** - Raw scan data

## Process:
1. Run scan: `python main.py` → creates `*_features.json`
2. Auto-label: `python utils/labeler.py data/*_features.json` → creates `labeled_*.json`
3. Add only `labeled_*.json` to git: `git add data/labeled_*.json`

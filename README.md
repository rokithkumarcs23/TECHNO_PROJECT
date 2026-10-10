# Network Intrusion Detection System (NIDS) – Project Workspace

This workspace contains the complete implementation of the **Network Intrusion Detection System (NIDS)** in the [`network-intrusion-detection/`](network-intrusion-detection/) directory.

### Quick Start (Windows PowerShell)

```powershell
cd network-intrusion-detection
$env:PYTHONIOENCODING="utf-8"
python -m streamlit run app.py
```

Or run the test suite:
```powershell
cd network-intrusion-detection
python -m pytest tests/
```

Access the web dashboard in your browser at: **`http://localhost:8501`**

For comprehensive system documentation, architecture diagrams, and detailed threat engine methodology, see [`network-intrusion-detection/README.md`](network-intrusion-detection/README.md).

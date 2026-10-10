# PowerShell quick launcher for Network Intrusion Detection System (NIDS)
$Host.UI.RawUI.WindowTitle = "NIDS - Network Intrusion Detection Dashboard"
$env:PYTHONIOENCODING = "utf-8"

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "🛡️ Network Intrusion Detection System (NIDS)" -ForegroundColor Green
Write-Host "Threat Detection & Security Monitoring Dashboard" -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

# Check if sample PCAP exists, if not generate it
if (-not (Test-Path "data/sample_traffic.pcap")) {
    Write-Host "[+] Generating demo synthetic PCAP..." -ForegroundColor Yellow
    python data/generate_sample_pcap.py
}

Write-Host "[+] Starting Streamlit SOC Web Dashboard on http://localhost:8501..." -ForegroundColor Green
python -m streamlit run app.py

"""
Network Intrusion Detection System (NIDS) – Threat Detection and Security Monitoring
Main Streamlit Web Application Dashboard.
Provides real-time packet inspection, rule-based threat detection,
Plotly analytics visualizations, and persistent SQLite event auditing.
"""

import os
import sys
import json
import time
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st
from datetime import datetime

# Add project root to sys.path
PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from modules.database import (
    init_db,
    get_alerts,
    get_alerts_dataframe,
    get_alert_counts,
    clear_all_alerts,
    export_alerts_to_csv,
    DEFAULT_DB_PATH
)
from modules.packet_capture import (
    read_pcap_file,
    parse_packets_to_dataframe,
    check_live_capture_status,
    get_available_interfaces,
    capture_live_packets
)
from modules.packet_analyzer import (
    compute_traffic_metrics,
    get_protocol_distribution,
    get_packets_over_time,
    get_top_sources,
    get_top_destinations,
    get_destination_ports_summary
)
from modules.detection_engine import (
    DetectionEngine,
    DEFAULT_PORT_SCAN_THRESHOLD,
    DEFAULT_PORT_SCAN_WINDOW,
    DEFAULT_BRUTE_FORCE_THRESHOLD,
    DEFAULT_BRUTE_FORCE_WINDOW,
    DEFAULT_FLOODING_THRESHOLD,
    DEFAULT_FLOODING_WINDOW,
    DEFAULT_ALERT_COOLDOWN
)
from modules.alert_manager import AlertManager


# -----------------------------------------------------------------------------
# Streamlit Page Configuration & Cyber Dark Styling
# -----------------------------------------------------------------------------
st.set_page_config(
    page_title="NIDS - Network Threat Monitoring",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom Cyber Dark CSS
st.markdown("""
<style>
    /* Main container background */
    .stApp {
        background-color: #0b1120;
        color: #f1f5f9;
        font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
    }

    /* Sidebar styling */
    [data-testid="stSidebar"] {
        background-color: #070d18;
        border-right: 1px solid #1e293b;
    }

    /* Metric Cards */
    div[data-testid="stMetric"] {
        background: linear-gradient(135deg, #111e38 0%, #0d172a 100%);
        border: 1px solid #1e3a5f;
        padding: 14px 18px;
        border-radius: 10px;
        box-shadow: 0 4px 14px rgba(0, 0, 0, 0.4);
    }
    div[data-testid="stMetric"]:hover {
        border-color: #0284c7;
        transform: translateY(-1px);
        transition: all 0.2s ease-in-out;
    }
    div[data-testid="stMetricLabel"] {
        color: #94a3b8 !important;
        font-size: 0.85rem !important;
        font-weight: 600 !important;
        text-transform: uppercase;
        letter-spacing: 0.05em;
    }
    div[data-testid="stMetricValue"] {
        color: #38bdf8 !important;
        font-weight: 700 !important;
        font-size: 1.8rem !important;
    }

    /* Custom Header Banner */
    .soc-header {
        background: linear-gradient(90deg, #0f1f3d 0%, #0c182f 50%, #081020 100%);
        border: 1px solid #1e3a5f;
        border-radius: 12px;
        padding: 20px 24px;
        margin-bottom: 22px;
        display: flex;
        justify-content: space-between;
        align-items: center;
    }
    .soc-title {
        font-size: 1.6rem;
        font-weight: 800;
        color: #f8fafc;
        margin: 0;
        letter-spacing: -0.02em;
    }
    .soc-subtitle {
        color: #38bdf8;
        font-size: 0.9rem;
        margin: 4px 0 0 0;
        font-weight: 500;
    }
    .soc-badge {
        display: inline-block;
        padding: 6px 14px;
        border-radius: 20px;
        font-size: 0.8rem;
        font-weight: 700;
        letter-spacing: 0.05em;
        text-transform: uppercase;
    }
    .badge-normal {
        background-color: rgba(16, 185, 129, 0.15);
        color: #34d399;
        border: 1px solid #059669;
    }
    .badge-elevated {
        background-color: rgba(245, 158, 11, 0.15);
        color: #fbbf24;
        border: 1px solid #d97706;
    }
    .badge-critical {
        background-color: rgba(239, 68, 68, 0.15);
        color: #f87171;
        border: 1px solid #dc2626;
    }

    /* Alert cards */
    .alert-card {
        background: #0f1b31;
        border-left: 5px solid #3b82f6;
        border-top: 1px solid #1e293b;
        border-right: 1px solid #1e293b;
        border-bottom: 1px solid #1e293b;
        border-radius: 8px;
        padding: 12px 16px;
        margin-bottom: 10px;
    }
    .alert-card-high {
        border-left-color: #ef4444;
        background: linear-gradient(90deg, rgba(239, 68, 68, 0.08) 0%, #0f1b31 35%);
    }
    .alert-card-medium {
        border-left-color: #f59e0b;
        background: linear-gradient(90deg, rgba(245, 158, 11, 0.08) 0%, #0f1b31 35%);
    }
    .alert-card-low {
        border-left-color: #10b981;
    }

    /* Tab styles */
    .stTabs [data-baseweb="tab-list"] {
        gap: 8px;
        background-color: #070d18;
        padding: 8px 12px;
        border-radius: 10px;
        border: 1px solid #1e293b;
    }
    .stTabs [data-baseweb="tab"] {
        color: #94a3b8;
        border-radius: 6px;
        font-weight: 600;
        padding: 8px 16px;
    }
    .stTabs [aria-selected="true"] {
        background-color: #0284c7 !important;
        color: #ffffff !important;
    }
</style>
""", unsafe_allow_html=True)


# -----------------------------------------------------------------------------
# Initialize Session State
# -----------------------------------------------------------------------------
if "db_initialized" not in st.session_state:
    init_db()
    st.session_state["db_initialized"] = True

if "alert_manager" not in st.session_state:
    st.session_state["alert_manager"] = AlertManager()

if "parsed_packets" not in st.session_state:
    st.session_state["parsed_packets"] = []

if "packets_df" not in st.session_state:
    st.session_state["packets_df"] = pd.DataFrame()

if "active_mode" not in st.session_state:
    st.session_state["active_mode"] = "Offline PCAP Analysis"

if "analysis_timestamp" not in st.session_state:
    st.session_state["analysis_timestamp"] = None


# -----------------------------------------------------------------------------
# Sidebar Configuration & Controls
# -----------------------------------------------------------------------------
with st.sidebar:
    st.markdown("## 🛡️ NIDS Control Center")
    st.markdown("<span style='color: #94a3b8; font-size: 0.85rem;'>Threat Detection & Security Monitoring</span>", unsafe_allow_html=True)
    st.markdown("---")

    # Mode Selector: Default is Offline PCAP Analysis
    input_mode = st.radio(
        "Capture & Ingestion Mode",
        options=["Offline PCAP Analysis", "Live Network Capture"],
        index=0,
        help="Select offline PCAP inspection (default, non-privileged) or live network adapter capture."
    )
    st.session_state["active_mode"] = input_mode

    st.markdown("---")

    if input_mode == "Offline PCAP Analysis":
        st.markdown("### 📁 PCAP File Ingestion")
        uploaded_file = st.file_uploader(
            "Upload .pcap or .pcapng file",
            type=["pcap", "pcapng"],
            help="Select an offline network packet capture file for automated rule-based analysis."
        )

        sample_pcap_path = os.path.join(PROJECT_ROOT, "data", "sample_traffic.pcap")
        col_s1, col_s2 = st.columns(2)
        with col_s1:
            if st.button("⚡ Demo Attacks", use_container_width=True, help="Generate and inspect synthetic PCAP containing port scans, brute-force indicators, and traffic floods"):
                from data.generate_sample_pcap import generate_synthetic_pcap
                with st.spinner("Generating demo synthetic PCAP..."):
                    generate_synthetic_pcap(sample_pcap_path)
                    packets, err = read_pcap_file(sample_pcap_path)
                    if err:
                        st.error(err)
                    else:
                        st.session_state["parsed_packets"] = packets
                        st.session_state["packets_df"] = parse_packets_to_dataframe(packets)
                        st.session_state["analysis_timestamp"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                        st.success(f"Loaded {len(packets)} synthetic packets!")
                        st.rerun()

        with col_s2:
            max_pkts = st.number_input("Max Packets", min_value=50, max_value=50000, value=2500, step=500)

        if uploaded_file is not None:
            if st.button("🚀 Analyze Uploaded PCAP", use_container_width=True, type="primary"):
                with st.spinner("Parsing and analyzing PCAP stream..."):
                    bytes_data = uploaded_file.read()
                    packets, err = read_pcap_file(bytes_data, max_packets=max_pkts)
                    if err:
                        st.error(f"Error parsing file: {err}")
                    else:
                        st.session_state["parsed_packets"] = packets
                        st.session_state["packets_df"] = parse_packets_to_dataframe(packets)
                        st.session_state["analysis_timestamp"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                        st.success(f"Parsed {len(packets)} packets successfully.")
                        st.rerun()

    else:
        # Live Network Monitoring Section
        st.markdown("### 📡 Live Packet Capture")
        is_supported, cap_msg = check_live_capture_status()

        if not is_supported:
            st.warning(f"⚠️ {cap_msg}")
            st.info("💡 Tip: Use 'Offline PCAP Analysis' to analyze test traffic without administrator rights.")
        else:
            st.success("✅ Capture driver detected.")

        interfaces = get_available_interfaces()
        selected_iface = st.selectbox("Interface", options=interfaces, index=0)

        col_c1, col_c2 = st.columns(2)
        with col_c1:
            live_count = st.number_input("Packets", min_value=10, max_value=2000, value=100, step=20)
        with col_c2:
            live_timeout = st.number_input("Timeout (s)", min_value=2, max_value=60, value=6, step=2)

        if st.button("🔴 Start Live Capture", use_container_width=True, type="primary"):
            with st.spinner(f"Sniffing on {selected_iface} (Up to {live_count} packets)..."):
                pkts, err = capture_live_packets(
                    interface=selected_iface if selected_iface != "Default" else None,
                    packet_count=live_count,
                    timeout=live_timeout
                )
                if err:
                    st.error(err)
                elif not pkts:
                    st.warning("No packets captured during timeout window.")
                else:
                    st.session_state["parsed_packets"] = pkts
                    st.session_state["packets_df"] = parse_packets_to_dataframe(pkts)
                    st.session_state["analysis_timestamp"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    st.success(f"Captured {len(pkts)} packets.")
                    st.rerun()

    st.markdown("---")
    st.markdown("### ⚙️ Detection Thresholds")

    with st.expander("🔍 Rule Configuration", expanded=False):
        ps_thresh = st.slider("Port Scan: Port Threshold", min_value=5, max_value=100, value=DEFAULT_PORT_SCAN_THRESHOLD, step=1)
        ps_win = st.slider("Port Scan: Window (s)", min_value=2.0, max_value=60.0, value=DEFAULT_PORT_SCAN_WINDOW, step=1.0)

        bf_thresh = st.slider("Brute-Force: Attempts", min_value=3, max_value=50, value=DEFAULT_BRUTE_FORCE_THRESHOLD, step=1)
        bf_win = st.slider("Brute-Force: Window (s)", min_value=5.0, max_value=180.0, value=DEFAULT_BRUTE_FORCE_WINDOW, step=5.0)

        flood_thresh = st.slider("Flooding: Packet Threshold", min_value=20, max_value=500, value=DEFAULT_FLOODING_THRESHOLD, step=10)
        flood_win = st.slider("Flooding: Window (s)", min_value=1.0, max_value=30.0, value=DEFAULT_FLOODING_WINDOW, step=0.5)

        cooldown = st.slider("Alert Cooldown (s)", min_value=5.0, max_value=120.0, value=DEFAULT_ALERT_COOLDOWN, step=5.0)

    st.markdown("---")
    st.markdown("### 🗄️ Database Management")
    if st.button("🗑️ Clear Stored Alerts", use_container_width=True):
        clear_all_alerts()
        st.session_state["alert_manager"].clear_database()
        st.success("All database alerts deleted.")
        st.rerun()


# -----------------------------------------------------------------------------
# Trigger Threat Detection on Active Packets
# -----------------------------------------------------------------------------
engine = DetectionEngine(
    port_scan_threshold=ps_thresh,
    port_scan_window=ps_win,
    brute_force_threshold=bf_thresh,
    brute_force_window=bf_win,
    flooding_threshold=flood_thresh,
    flooding_window=flood_win,
    cooldown_seconds=cooldown
)

# Process packets if present and not yet processed for this batch
current_packets = st.session_state["parsed_packets"]
if current_packets and st.session_state.get("last_processed_timestamp") != st.session_state["analysis_timestamp"]:
    detected_alerts = engine.process_packet_stream(current_packets)
    st.session_state["alert_manager"].record_alerts(detected_alerts, persist=True)
    st.session_state["last_processed_timestamp"] = st.session_state["analysis_timestamp"]


# -----------------------------------------------------------------------------
# Main Header & Real-Time SOC Status Banner
# -----------------------------------------------------------------------------
counts = get_alert_counts()
total_alerts = counts["total"]
high_count = counts["high_severity"]

if high_count > 0:
    threat_badge = '<span class="soc-badge badge-critical">CRITICAL THREATS DETECTED</span>'
elif total_alerts > 0:
    threat_badge = '<span class="soc-badge badge-elevated">ELEVATED ACTIVITY</span>'
else:
    threat_badge = '<span class="soc-badge badge-normal">SYSTEM HEALTHY • NO THREATS</span>'

header_html = f"""
<div class="soc-header">
    <div>
        <div class="soc-title">🛡️ Network Intrusion Detection System</div>
        <div class="soc-subtitle">Real-Time Threat Detection, Packet Telemetry & Security Incident Monitoring</div>
    </div>
    <div style="text-align: right;">
        {threat_badge}
        <div style="color: #64748b; font-size: 0.75rem; margin-top: 6px;">Mode: {st.session_state['active_mode']}</div>
    </div>
</div>
"""
st.markdown(header_html, unsafe_allow_html=True)


# -----------------------------------------------------------------------------
# Metric Overview Cards
# -----------------------------------------------------------------------------
packets_df = st.session_state["packets_df"]
total_pkts_count = len(packets_df) if not packets_df.empty else 0

col_m1, col_m2, col_m3, col_m4, col_m5 = st.columns(5)
col_m1.metric("Packets Analyzed", f"{total_pkts_count:,}")
col_m2.metric("Total Alerts", f"{total_alerts:,}", delta=f"{high_count} High" if high_count > 0 else None, delta_color="inverse")
col_m3.metric("Port Scans", f"{counts['port_scan']:,}")
col_m4.metric("Brute-Force", f"{counts['brute_force']:,}")
col_m5.metric("Traffic Floods", f"{counts['flooding']:,}")

st.markdown("<div style='height: 14px;'></div>", unsafe_allow_html=True)


# -----------------------------------------------------------------------------
# Primary Navigation Tabs
# -----------------------------------------------------------------------------
tab_alerts, tab_charts, tab_packets, tab_history, tab_docs = st.tabs([
    "🚨 Security Alerts",
    "📊 Traffic Analytics",
    "🔍 Packet Inspector",
    "🗃️ Event History (SQLite)",
    "📖 Security & Methodology"
])


# -----------------------------------------------------------------------------
# TAB 1: Real-Time Security Alerts Feed
# -----------------------------------------------------------------------------
with tab_alerts:
    st.markdown("### 🚨 Detected Security Events")

    alerts_list = get_alerts(limit=200)

    if not alerts_list:
        st.info("ℹ️ No security alerts detected yet. Upload a PCAP file or click **'⚡ Demo Attacks'** in the sidebar to run a demonstration.")
    else:
        # Filter controls
        f_col1, f_col2, f_col3 = st.columns(3)
        with f_col1:
            filter_sev = st.selectbox("Filter by Severity", ["All", "High", "Medium", "Low"], index=0)
        with f_col2:
            filter_type = st.selectbox(
                "Filter by Attack Category",
                ["All", "Port Scanning", "Suspected Brute-Force Attempt", "Suspected Traffic Flooding"],
                index=0
            )
        with f_col3:
            filter_ip = st.text_input("Filter by Source IP", "")

        filtered_alerts = get_alerts(
            limit=200,
            attack_type=filter_type,
            severity=filter_sev,
            source_ip=filter_ip
        )

        st.caption(f"Showing {len(filtered_alerts)} alert(s) matching filter criteria.")

        for a in filtered_alerts:
            sev_class = "alert-card-low"
            sev_color = "#34d399"
            if a["severity"].upper() == "HIGH":
                sev_class = "alert-card-high"
                sev_color = "#f87171"
            elif a["severity"].upper() == "MEDIUM":
                sev_class = "alert-card-medium"
                sev_color = "#fbbf24"

            with st.container():
                st.markdown(f"""
                <div class="alert-card {sev_class}">
                    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 6px;">
                        <div>
                            <span style="font-weight: 700; color: {sev_color}; font-size: 0.95rem;">[{a['severity'].upper()}]</span>
                            <span style="font-weight: 700; color: #f8fafc; font-size: 1.05rem; margin-left: 8px;">{a['attack_type']}</span>
                        </div>
                        <span style="color: #94a3b8; font-size: 0.8rem; font-family: monospace;">⏱️ {a['timestamp']}</span>
                    </div>
                    <div style="color: #cbd5e1; font-size: 0.9rem; margin-bottom: 8px;">
                        {a['description']}
                    </div>
                    <div style="font-size: 0.82rem; color: #64748b; font-family: monospace;">
                        <strong>Source:</strong> <span style="color: #38bdf8;">{a['source_ip']}</span> &nbsp;➔&nbsp;
                        <strong>Target:</strong> <span style="color: #cbd5e1;">{a['destination_ip']}</span>
                    </div>
                </div>
                """, unsafe_allow_html=True)

                if a.get("evidence"):
                    try:
                        ev_json = json.loads(a["evidence"])
                        with st.expander(f"🔎 Technical Evidence (Alert ID: {a['id'][:8]}...)", expanded=False):
                            st.json(ev_json)
                    except Exception:
                        with st.expander(f"🔎 Evidence Log (Alert ID: {a['id'][:8]}...)", expanded=False):
                            st.write(a["evidence"])


# -----------------------------------------------------------------------------
# TAB 2: Traffic Analytics & Plotly Visualizations
# -----------------------------------------------------------------------------
with tab_charts:
    st.markdown("### 📊 Network Traffic & Attack Analytics")

    if packets_df.empty:
        st.info("ℹ️ No packet data loaded to generate charts. Ingest a PCAP file or use the demo generator in the sidebar.")
    else:
        # Row 1: Protocol Distribution & Time Series
        chart_col1, chart_col2 = st.columns([1, 1])

        with chart_col1:
            proto_df = get_protocol_distribution(packets_df)
            if not proto_df.empty:
                fig_proto = px.pie(
                    proto_df,
                    names="protocol",
                    values="count",
                    title="Network Protocol Breakdown",
                    hole=0.45,
                    color_discrete_sequence=["#0284c7", "#38bdf8", "#059669", "#d97706", "#7c3aed", "#ec4899"]
                )
                fig_proto.update_layout(
                    paper_bgcolor="#0f172a",
                    plot_bgcolor="#0f172a",
                    font_color="#cbd5e1",
                    margin=dict(t=40, b=20, l=20, r=20)
                )
                st.plotly_chart(fig_proto, use_container_width=True)

        with chart_col2:
            time_df = get_packets_over_time(packets_df, bins=25)
            if not time_df.empty:
                fig_time = px.area(
                    time_df,
                    x="time_bucket",
                    y="packet_count",
                    title="Traffic Volume Timeline (Packets Observed)",
                    labels={"time_bucket": "Time", "packet_count": "Packet Count"}
                )
                fig_time.update_traces(line_color="#38bdf8", fillcolor="rgba(56, 189, 248, 0.2)")
                fig_time.update_layout(
                    paper_bgcolor="#0f172a",
                    plot_bgcolor="#0f172a",
                    font_color="#cbd5e1",
                    margin=dict(t=40, b=20, l=20, r=20),
                    xaxis=dict(gridcolor="#1e293b"),
                    yaxis=dict(gridcolor="#1e293b")
                )
                st.plotly_chart(fig_time, use_container_width=True)

        # Row 2: Top Sources & Target Services
        chart_col3, chart_col4 = st.columns([1, 1])

        with chart_col3:
            src_df = get_top_sources(packets_df, top_n=8)
            if not src_df.empty:
                fig_src = px.bar(
                    src_df,
                    x="packet_count",
                    y="source_ip",
                    orientation="h",
                    title="Top Traffic Sources (Talkers)",
                    labels={"packet_count": "Packets", "source_ip": "Source IP"},
                    color="packet_count",
                    color_continuous_scale="Blues"
                )
                fig_src.update_layout(
                    paper_bgcolor="#0f172a",
                    plot_bgcolor="#0f172a",
                    font_color="#cbd5e1",
                    margin=dict(t=40, b=20, l=20, r=20),
                    yaxis=dict(autorange="reversed", gridcolor="#1e293b"),
                    xaxis=dict(gridcolor="#1e293b")
                )
                st.plotly_chart(fig_src, use_container_width=True)

        with chart_col4:
            port_df = get_destination_ports_summary(packets_df, top_n=8)
            if not port_df.empty:
                fig_port = px.bar(
                    port_df,
                    x="port_label",
                    y="packet_count",
                    title="Target Destination Ports / Services",
                    labels={"port_label": "Port & Service", "packet_count": "Packet Count"},
                    color_discrete_sequence=["#38bdf8"]
                )
                fig_port.update_layout(
                    paper_bgcolor="#0f172a",
                    plot_bgcolor="#0f172a",
                    font_color="#cbd5e1",
                    margin=dict(t=40, b=20, l=20, r=20),
                    xaxis=dict(gridcolor="#1e293b"),
                    yaxis=dict(gridcolor="#1e293b")
                )
                st.plotly_chart(fig_port, use_container_width=True)

        # Row 3: Attack Category & Severity Breakdown
        if total_alerts > 0:
            st.markdown("#### 🎯 Threat Breakdown Visualizations")
            a_col1, a_col2 = st.columns(2)

            with a_col1:
                cat_data = pd.DataFrame([
                    {"Category": "Port Scanning", "Count": counts["port_scan"]},
                    {"Category": "Suspected Brute-Force", "Count": counts["brute_force"]},
                    {"Category": "Suspected Flooding", "Count": counts["flooding"]}
                ])
                cat_data = cat_data[cat_data["Count"] > 0]
                if not cat_data.empty:
                    fig_cat = px.bar(
                        cat_data,
                        x="Category",
                        y="Count",
                        title="Alerts by Threat Category",
                        color="Category",
                        color_discrete_sequence=["#ef4444", "#f59e0b", "#0284c7"]
                    )
                    fig_cat.update_layout(
                        paper_bgcolor="#0f172a",
                        plot_bgcolor="#0f172a",
                        font_color="#cbd5e1",
                        margin=dict(t=40, b=20, l=20, r=20),
                        yaxis=dict(gridcolor="#1e293b")
                    )
                    st.plotly_chart(fig_cat, use_container_width=True)

            with a_col2:
                sev_data = pd.DataFrame([
                    {"Severity": "High", "Count": counts["high_severity"], "Color": "#ef4444"},
                    {"Severity": "Medium", "Count": counts["medium_severity"], "Color": "#f59e0b"},
                    {"Severity": "Low", "Count": counts["low_severity"], "Color": "#10b981"}
                ])
                sev_data = sev_data[sev_data["Count"] > 0]
                if not sev_data.empty:
                    fig_sev = px.pie(
                        sev_data,
                        names="Severity",
                        values="Count",
                        title="Alert Severity Distribution",
                        hole=0.45,
                        color="Severity",
                        color_discrete_map={"High": "#ef4444", "Medium": "#f59e0b", "Low": "#10b981"}
                    )
                    fig_sev.update_layout(
                        paper_bgcolor="#0f172a",
                        plot_bgcolor="#0f172a",
                        font_color="#cbd5e1",
                        margin=dict(t=40, b=20, l=20, r=20)
                    )
                    st.plotly_chart(fig_sev, use_container_width=True)


# -----------------------------------------------------------------------------
# TAB 3: Packet Inspector & Metadata Table
# -----------------------------------------------------------------------------
with tab_packets:
    st.markdown("### 🔍 Raw Packet Inspector & Telemetry")

    if packets_df.empty:
        st.info("ℹ️ No packet stream available. Load a PCAP file to inspect raw packet fields.")
    else:
        # Traffic summary metrics
        metrics = compute_traffic_metrics(packets_df)
        p_col1, p_col2, p_col3, p_col4 = st.columns(4)
        p_col1.metric("Capture Duration", f"{metrics['duration_seconds']} sec")
        p_col2.metric("Total Volume", f"{(metrics['total_bytes'] / 1024):.1f} KB")
        p_col3.metric("Packet Rate", f"{metrics['packet_rate']} pkts/s")
        p_col4.metric("Average Size", f"{metrics['avg_packet_size']} bytes")

        st.markdown("<div style='height: 8px;'></div>", unsafe_allow_html=True)

        # Filters for the packet table
        t_col1, t_col2, t_col3 = st.columns(3)
        with t_col1:
            proto_opts = ["All"] + sorted([str(p) for p in packets_df["protocol"].unique() if pd.notna(p)])
            sel_proto = st.selectbox("Protocol Filter", proto_opts)
        with t_col2:
            search_ip = st.text_input("IP Address Search", "", placeholder="e.g. 192.168.1.105")
        with t_col3:
            syn_only = st.checkbox("Show SYN Packets Only (Scan/Handshake)", value=False)

        view_df = packets_df.copy()
        if sel_proto != "All":
            view_df = view_df[view_df["protocol"] == sel_proto]
        if search_ip.strip():
            view_df = view_df[
                view_df["source_ip"].str.contains(search_ip, na=False) |
                view_df["destination_ip"].str.contains(search_ip, na=False)
            ]
        if syn_only:
            view_df = view_df[view_df["is_syn"] == True]

        display_cols = [
            "index", "time_str", "source_ip", "source_port",
            "destination_ip", "destination_port", "protocol",
            "packet_size", "tcp_flags", "summary"
        ]
        available_cols = [c for c in display_cols if c in view_df.columns]

        st.caption(f"Displaying {len(view_df):,} of {len(packets_df):,} parsed packets.")
        st.dataframe(
            view_df[available_cols],
            use_container_width=True,
            height=420
        )


# -----------------------------------------------------------------------------
# TAB 4: Persistent SQLite Event History & Export
# -----------------------------------------------------------------------------
with tab_history:
    st.markdown("### 🗃️ Persistent SQLite Event Audit Log")
    st.markdown(
        "<span style='color: #94a3b8; font-size: 0.85rem;'>All alerts are permanently stored in SQLite and can be audited, filtered, and exported.</span>",
        unsafe_allow_html=True
    )

    h_col1, h_col2, h_col3 = st.columns(3)
    with h_col1:
        hist_attack = st.selectbox(
            "Filter Category",
            ["All", "Port Scanning", "Suspected Brute-Force Attempt", "Suspected Traffic Flooding"],
            key="hist_cat"
        )
    with h_col2:
        hist_sev = st.selectbox("Filter Severity", ["All", "High", "Medium", "Low"], key="hist_sev")
    with h_col3:
        hist_limit = st.slider("Record Limit", 50, 2000, 500, step=50)

    db_alerts_df = get_alerts_dataframe(
        limit=hist_limit,
        attack_type=hist_attack,
        severity=hist_sev
    )

    if db_alerts_df.empty:
        st.info("No records match the current database filter criteria.")
    else:
        st.dataframe(
            db_alerts_df[["timestamp", "source_ip", "destination_ip", "attack_type", "severity", "description"]],
            use_container_width=True,
            height=380
        )

        csv_data = db_alerts_df.to_csv(index=False).encode("utf-8")
        st.download_button(
            label="📥 Download Filtered Alerts as CSV",
            data=csv_data,
            file_name=f"nids_alerts_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
            mime="text/csv",
            use_container_width=False
        )


# -----------------------------------------------------------------------------
# TAB 5: Security Architecture & Operational Methodology
# -----------------------------------------------------------------------------
with tab_docs:
    st.markdown("### 📖 Detection Engine Architecture & Security Guidelines")

    st.markdown(r"""
    #### 1. Rule-Based Threat Detection Methodology
    The NIDS uses deterministic, stateful sliding time windows to detect anomalous network patterns without high false-positive rates:

    * **Port Scanning Detection**:
      * **Logic**: Evaluates the cardinality of distinct destination ports probed by a single source IP within a rolling time window $\Delta t$.
      * **Default Rule**: $> 20$ unique destination ports within $10.0$ seconds.
      * **Severity**: `High` if $\ge 40$ ports, otherwise `Medium`.

    * **Suspected Brute-Force Connection Indicators**:
      * **Logic**: Monitors repeated TCP SYN or connection initialization attempts to sensitive services (e.g., SSH port 22, RDP 3389, FTP 21, MySQL 3306).
      * **Default Rule**: $> 10$ connection attempts from the same source IP to the same service within $60.0$ seconds.
      * **Security Caveat**: Packet metadata indicates connection frequency; actual credential validation requires application-level authentication logs.

    * **Suspected Traffic Flooding (DoS/DDoS Indicator)**:
      * **Logic**: Measures source packet rate over short burst windows.
      * **Default Rule**: $> 100$ packets from a single source within $5.0$ seconds ($> 20$ pkts/s).
      * **Severity**: `High` if $\ge 200$ packets, otherwise `Medium`.

    * **Deduplication & Cooldown Control**:
      * Prevents redundant alerts for ongoing attack sessions by suppressing duplicate alerts for the same source, attack type, and target within a configurable cooldown window (default $20.0$ seconds).

    ---
    #### 2. Live Capture Permissions & Prerequisites
    * **Windows**:
      * Requires **Npcap** (https://npcap.com/) installed with "WinPcap API-compatible mode" enabled.
      * Streamlit or terminal must be launched with Administrator privileges.
    * **Linux**:
      * Requires raw socket capabilities:
        ```bash
        sudo setcap cap_net_raw,cap_net_admin=eip $(which python)
        ```
        or run under `sudo`.

    ---
    #### 3. Ethical Security & Privacy Standards
    * **Authorization**: Only monitor networks where explicit administrative authorization has been granted.
    * **Data Privacy**: The system extracts packet metadata (IPs, ports, headers) and avoids storing or displaying payload contents, credentials, or sensitive application data.
    """)

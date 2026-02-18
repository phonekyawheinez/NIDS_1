import streamlit as st
import pandas as pd
import glob
import plotly.express as px
import time
import os

# --- 1. CONFIGURATION & PAGE SETUP ---
st.set_page_config(
    page_title="NIDS Security Center",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# --- 2. SIDEBAR CONTROLS ---
with st.sidebar:
    st.title("🛡️ NIDS Console")
    st.success("System Active")
    st.divider()

    st.subheader("⚙️ Settings")
    auto_refresh = st.checkbox("Live Auto-Refresh", value=True)
    refresh_rate = st.slider("Refresh Rate (seconds)", 1, 10, 3)

    # Path inside the Docker container
    DATA_PATH = "/app/stream_output/*.json"

    if st.button("Manual Refresh"):
        st.rerun()


# --- 3. DATA LOADING FUNCTION ---
def load_data(path_pattern):
    files = glob.glob(path_pattern)
    # Filter out empty files or hidden Spark files (like metadata)
    files = [f for f in files if os.path.getsize(f) > 0 and not f.endswith('.crc')]

    if not files:
        return pd.DataFrame()

    dfs = []
    for f in files:
        try:
            # Spark JSON files are 'jsonlines' format
            temp_df = pd.read_json(f, lines=True)
            if not temp_df.empty:
                dfs.append(temp_df)
        except Exception:
            # Skip files that are currently being locked/written by Spark
            continue

    if not dfs:
        return pd.DataFrame()

    df = pd.concat(dfs, ignore_index=True)

    # Convert Spark timestamp string to datetime object
    if 'timestamp' in df.columns:
        df['timestamp'] = pd.to_datetime(df['timestamp'])
        df = df.sort_values('timestamp', ascending=False)  # Latest first

    return df


# --- 4. MAIN DASHBOARD LOGIC ---

st.title("🛰️ Real-Time Network Intrusion Detection")

df = load_data(DATA_PATH)

if df.empty:
    st.info("🕒 **Waiting for Spark Stream...** Make sure `nids_spark` is running and Zeek is generating traffic.")
    st.caption(f"Searching for JSON files in: {DATA_PATH}")
else:
    # -- CALCULATIONS --
    total_events = len(df)
    # Ensure 'attack_type' column exists (Spark might not have written it yet)
    if 'attack_type' not in df.columns:
        df['attack_type'] = 'Processing...'

    attacks = df[df['attack_type'] != 'Normal']
    atk_count = len(attacks)
    clean_count = total_events - atk_count
    threat_level = (atk_count / total_events) * 100 if total_events > 0 else 0

    # -- KPI ROW --
    col1, col2, col3, col4 = st.columns(4)
    col1.metric("TOTAL EVENTS", f"{total_events:,}")
    col2.metric("CLEAN TRAFFIC", f"{clean_count:,}")
    col3.metric("ATTACKS DETECTED", atk_count, delta=f"{atk_count} new" if atk_count > 0 else None,
                delta_color="inverse")
    col4.metric("THREAT LEVEL", f"{threat_level:.1f}%")

    # -- ALERTS SECTION --
    if atk_count > 0:
        latest_atk = attacks.iloc[0]  # Using index 0 because we sorted by latest first
        st.error(
            f"🚨 **CRITICAL ALERT:** {latest_atk['attack_type']} detected! "
            f"| Source: {latest_atk.get('src_ip', 'Unknown')} "
            f"| Target: {latest_atk.get('dst_ip', 'Unknown')}"
        )
    else:
        st.success("✅ **NETWORK SECURE:** Monitoring incoming traffic from Zeek.")

    # -- CHARTS ROW --
    c1, c2 = st.columns([2, 1])

    with c1:
        if 'timestamp' in df.columns:
            # Resample traffic to see volume over time
            df_time = df.set_index('timestamp').resample('5s').size().reset_index(name='packets')
            fig_line = px.line(df_time, x='timestamp', y='packets', title="Traffic Throughput (5s window)")
            fig_line.update_traces(line_color='#00CC96', fill='tozeroy')
            fig_line.update_layout(template="plotly_dark", height=300)
            st.plotly_chart(fig_line, use_container_width=True)

    with c2:
        counts = df['attack_type'].value_counts()
        fig_pie = px.pie(values=counts.values, names=counts.index, title="Threat Mix", hole=0.4)
        fig_pie.update_layout(template="plotly_dark", height=300, showlegend=False)
        st.plotly_chart(fig_pie, use_container_width=True)

    # -- DATA TABLE --
    st.subheader("📝 Live Detection Logs")

    # Selecting columns based on what your Spark script actually outputs
    display_cols = ['timestamp', 'src_ip', 'dst_ip', 'attack_type']
    available_cols = [c for c in display_cols if c in df.columns]


    def style_threats(val):
        return 'color: #ff4b4b; font-weight: bold' if val != 'Normal' else 'color: #21c354'


    st.dataframe(
        df[available_cols].head(20).style.map(style_threats, subset=['attack_type']),
        use_container_width=True,
        hide_index=True
    )

# --- 5. AUTO REFRESH TRIGGER ---
if auto_refresh:
    time.sleep(refresh_rate)
    st.rerun()
import streamlit as st
import pandas as pd
import glob
import plotly.express as px
import time

# --- 1. CONFIGURATION & PAGE SETUP ---
st.set_page_config(
    page_title="NIDS Security Center",
    page_icon="-",
    layout="wide",
    initial_sidebar_state="expanded"
)

# --- 2. SIDEBAR CONTROLS ---
with st.sidebar:
    st.title("NIDS Console")
    st.success("System Active")
    st.divider()

    st.subheader("⚙️ Settings")
    # Control the refresh state
    auto_refresh = st.checkbox("Live Auto-Refresh", value=True)
    refresh_rate = st.slider("Refresh Rate (seconds)", 1, 10, 5)
    DATA_PATH = st.text_input("Data Source", "../stream_output/*.json")

    if st.button("Manual Refresh"):
        st.rerun()


# --- 3. DATA LOADING FUNCTION ---
# We cache this lightly so it doesn't freeze the UI, but usually for live files we read fresh
def load_data(path):
    files = glob.glob(path)
    if not files:
        return pd.DataFrame()

    dfs = []
    for f in files:
        try:
            # Try reading json; if a file is currently being written to, it might fail.
            # We catch the error to prevent the dashboard from crashing.
            dfs.append(pd.read_json(f, lines=True))
        except ValueError:
            continue

    if not dfs:
        return pd.DataFrame()

    df = pd.concat(dfs, ignore_index=True)

    # Ensure timestamp is datetime
    if 'timestamp' in df.columns:
        df['timestamp'] = pd.to_datetime(df['timestamp'])
        df = df.sort_values('timestamp')

    return df


# --- 4. MAIN DASHBOARD LOGIC ---

# Load Data
df = load_data(DATA_PATH)

st.title("Network Intrusion Detection System")

if df.empty:
    st.warning("Waiting for data stream... No JSON files found in source path.")
else:
    # -- CALCULATIONS --
    total_pkts = len(df)
    attacks = df[df['attack_type'] != 'Normal']
    atk_count = len(attacks)
    clean_count = total_pkts - atk_count
    threat_level = (atk_count / total_pkts) * 100 if total_pkts > 0 else 0

    # -- KPI ROW --
    col1, col2, col3, col4 = st.columns(4)
    col1.metric("TOTAL PACKETS", f"{total_pkts:,}")
    col2.metric("CLEAN TRAFFIC", f"{clean_count:,}")
    col3.metric("ATTACKS", atk_count, delta=atk_count if atk_count > 0 else None, delta_color="inverse")
    col4.metric("THREAT LEVEL", f"{threat_level:.1f}%")

    # -- ALERTS SECTION --
    if atk_count > 0:
        latest_atk = attacks.iloc[-1]
        st.error(
            f"🚨 **CRITICAL ALERT:** {latest_atk['attack_type']} detected! "
            f"Protocol: {latest_atk.get('proto', 'TCP')} | "
            f"Source: {latest_atk.get('src_ip', 'Unknown')}"
        )
    else:
        st.success("✅ NETWORK SECURE: No active threats detected.")

    # -- CHARTS ROW --
    c1, c2 = st.columns([2, 1])

    with c1:
        # Time Series Chart
        if 'timestamp' in df.columns:
            # Resample to 1 second intervals for the chart
            df_time = df.set_index('timestamp').resample('1s').size().reset_index(name='packets')

            fig_line = px.area(
                df_time, x='timestamp', y='packets',
                title="Real-Time Traffic Volume",
                color_discrete_sequence=['#00CC96']
            )
            fig_line.update_layout(height=350, template="plotly_dark")
            # Unique key prevents rendering issues
            st.plotly_chart(fig_line, width= "content", key=f"line_{time.time()}")

    with c2:
        # Pie Chart
        counts = df['attack_type'].value_counts()
        fig_pie = px.pie(
            values=counts.values, names=counts.index,
            title="Threat Distribution",
            hole=0.4,
            color_discrete_sequence=px.colors.sequential.RdBu_r
        )
        fig_pie.update_layout(height=350, template="plotly_dark", showlegend=False)
        st.plotly_chart(fig_pie, width= "content", key=f"pie_{time.time()}")

    # -- DATA TABLE --
    st.subheader("Live Packet Log")

    # Select specific columns to display
    display_cols = ['timestamp', 'src_ip', 'dst_ip', 'proto', 'length', 'attack_type']
    # Filter only columns that exist in the dataframe
    actual_cols = [c for c in display_cols if c in df.columns]


    # Styling function for the table
    def style_threats(val):
        color = '#ff4b4b' if val != 'Normal' else '#21c354'
        return f'color: {color}'


    st.dataframe(
        df.tail(15)[actual_cols].style.map(style_threats, subset=['attack_type']),
        width="content",
        hide_index=True
    )

# --- 5. AUTO REFRESH TRIGGER ---
if auto_refresh:
    time.sleep(refresh_rate)
    st.rerun()
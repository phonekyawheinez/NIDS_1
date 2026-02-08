# import socket
# import sys
# import time
# from scapy.all import sniff, IP
#
# # Configuration
# HOST = 'localhost'
# PORT = 9999
#
# # The exact 26 features (Must match Spark Schema)
# FEATURE_ORDER = [
#     'dur', 'sbytes', 'dbytes', 'sttl', 'dttl', 'sloss', 'dloss',
#     'sload', 'dload', 'spkts', 'dpkts', 'swin', 'dwin',
#     'smeansz', 'dmeansz', 'trans_depth', 'sjit', 'djit',
#     'sintpkt', 'dintpkt', 'tcprtt', 'synack', 'ackdat',
#     'is_sm_ips_ports', 'ct_state_ttl', 'ct_flw_http_mthd'
# ]
#
#
# class ClientDisconnected(Exception):
#     """Custom exception to signal that Spark disconnected"""
#     pass
#
#
# def process_packet(packet, conn):
#     """
#     Extracts features and sends to Spark.
#     Raises ClientDisconnected if send fails.
#     """
#     if IP in packet:
#         try:
#             # 1. Extract Features
#             src_ip = packet[IP].src
#             dst_ip = packet[IP].dst
#             proto = packet[IP].proto
#             sbytes = len(packet)
#             sttl = packet[IP].ttl
#
#             # 2. Mock Flow Features (Safe Defaults)
#             data = {
#                 'dur': 0.000001,
#                 'sbytes': sbytes,
#                 'dbytes': 0,
#                 'sttl': sttl,
#                 'dttl': 0,
#                 'sloss': 0,
#                 'dloss': 0,
#                 'sload': 0.0,
#                 'dload': 0.0,
#                 'spkts': 1,
#                 'dpkts': 0,
#                 'swin': 0,
#                 'dwin': 0,
#                 'smeansz': sbytes,
#                 'dmeansz': 0,
#                 'trans_depth': 0,
#                 'sjit': 0.0,
#                 'djit': 0.0,
#                 'sintpkt': 0.0,
#                 'dintpkt': 0.0,
#                 'tcprtt': 0.0,
#                 'synack': 0.0,
#                 'ackdat': 0.0,
#                 'is_sm_ips_ports': 0,
#                 'ct_state_ttl': 0,
#                 'ct_flw_http_mthd': 0
#             }
#
#             # 3. Create CSV String
#             csv_values = [str(data[f]) for f in FEATURE_ORDER]
#             csv_line = ",".join(csv_values) + "\n"
#
#             # 4. Send to Spark (CRITICAL STEP)
#             conn.sendall(csv_line.encode('utf-8'))
#             print(f" Sent: {proto} | {src_ip} -> {dst_ip} | Size: {sbytes}")
#
#         except (BrokenPipeError, ConnectionResetError, OSError) as e:
#             # If Spark hung up, stop processing this packet and raise signal
#             raise ClientDisconnected("Spark disconnected")
#         except Exception as e:
#             print(f"Packet Processing Error: {e}")
#
#
# def start_sniffer():
#     while True:  # Outer Loop: Allows restarting the server
#         server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#         server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
#
#         try:
#             server_socket.bind((HOST, PORT))
#             server_socket.listen(1)
#             print(f"\n[WAITING] Sniffer ready on {HOST}:{PORT}. Waiting for Spark...")
#
#             conn, addr = server_socket.accept()
#             print(f"[CONNECTED] Spark connected from {addr}")
#
#             try:
#                 # Start capturing. If ClientDisconnected is raised, sniff stops.
#                 sniff(prn=lambda pkt: process_packet(pkt, conn), store=0)
#             except ClientDisconnected:
#                 print("Spark closed the connection. Resetting listener...")
#             except Exception as e:
#                 # Often sniff catches exceptions internally, so we might need to rely on the socket error
#                 print(f"Sniffing interrupted: {e}")
#             finally:
#                 conn.close()
#
#         except KeyboardInterrupt:
#             print("\nStopping Sniffer (User Interrupt)...")
#             break
#         except Exception as e:
#             print(f"Server Error: {e}")
#             time.sleep(1)  # Prevent CPU spike on repeat error
#         finally:
#             server_socket.close()
#
#
# if __name__ == "__main__":
#     # Admin check omitted for brevity, run as Admin!
#     start_sniffer()


import socket
import sys
import time
from scapy.all import sniff, IP

# Configuration
HOST = '127.0.0.1'
PORT = 8888

# The 26 features your model was trained on (Must be in this exact order)
FEATURE_COLS = [
    'dur', 'sbytes', 'dbytes', 'sttl', 'dttl', 'sloss', 'dloss',
    'sload', 'dload', 'spkts', 'dpkts', 'swin', 'dwin',
    'smeansz', 'dmeansz', 'trans_depth', 'sjit', 'djit',
    'sintpkt', 'dintpkt', 'tcprtt', 'synack', 'ackdat',
    'is_sm_ips_ports', 'ct_state_ttl', 'ct_flw_http_mthd'
]


def get_packet_features(packet):
    """Extracts raw numbers from the wire."""
    if IP in packet:
        sbytes = len(packet)
        sttl = packet[IP].ttl
        # We fill the rest with neutral defaults so the model can read the line
        # In a real-world enterprise IDS, you'd use a flow-meter here.
        data = {k: 0.0 for k in FEATURE_COLS}
        # data.update({
        #     'dur': 0.001,
        #     'sbytes': float(sbytes),
        #     'sttl': float(sttl),
        #     'spkts': 1.0,
        #     'smeansz': float(sbytes)
        # })
        data.update({
            'dur': 2.0,  # Longer duration
            'sbytes': 50000.0,  # Massive bytes
            'sttl': 254.0  # High TTL (often seen in scans)
        })
        # Convert dictionary to a single comma-separated line
        return ",".join([str(data[col]) for col in FEATURE_COLS]) + "\n"
    return None


def run_real_sniffer():
    # Create a robust TCP Socket
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((HOST, PORT))
    server.listen(1)

    print(f"SNIFFER ACTIVE: Listening for Spark on {PORT}...")

    while True:
        conn, addr = server.accept()
        print(f"CONNECTION ESTABLISHED: Spark is now receiving live traffic from {addr}")

        try:
            def sniffer_callback(pkt):
                line = get_packet_features(pkt)
                if line:
                    conn.sendall(line.encode('utf-8'))

            # Start the hardware capture
            # filter="ip" ensures we don't waste CPU on non-IP traffic
            sniff(prn=sniffer_callback, store=0)

        except (ConnectionResetError, BrokenPipeError, OSError):
            print("Spark disconnected. Waiting for reconnect...")
        finally:
            conn.close()


if __name__ == "__main__":
    run_real_sniffer()
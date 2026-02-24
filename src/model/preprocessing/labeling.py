import pandas as pd
import numpy as np
import os
from pathlib import Path

ROOT_DIR = os.path.join(Path(__file__).resolve().parent.parent, "dataset")

# =====================================
# ---   Labeling Helper Functions   ---
# =====================================

def read_csv(path: str) -> pd.DataFrame:
    return pd.read_csv(path, low_memory=False).copy()

def http_flood_labeler(input_csv: str, out_csv: str, start_time: int, end_time: int) -> None:
    """
    Labels HTTP flood attack traffic within a time window from a specific attack IP,
    identified by non-null UDP destination port.

    Inputs:
    - input_csv: Path to the raw input CSV file to be labeled.
    - out_csv: Path to save the labeled output CSV file.
    - start_time: Start of the attack time window.
    - end_time: End of the attack time window.

    """
    new = read_csv(input_csv)
    new["Label"] = "Normal"

    mask = (
            (new["frame.time_relative"] > start_time) &
            (new["frame.time_relative"] < end_time) &
            ((new["ip.src"] == "85.75.109.194") | (new["ip.dst"] == "85.75.109.194")) &
            (new["udp.dstport"].notnull())
    )

    new.loc[mask, "Label"] = "http-flood"
    print(f"{input_csv.removesuffix('.csv')} -> samples for http-flood: {np.sum(new['Label'] == 'http-flood')}")
    new.to_csv(out_csv, index=False)


def fuzzing_labeler(input_csv: str, out_csv: str, start_time: int, end_time: int) -> None:
    """
    Labels fuzzing attack traffic within a time window from a specific attack IP,
    identified by null QUIC packet length (non-QUIC packets sent to a QUIC server).

    Inputs:
    - input_csv: Path to the raw input CSV file to be labeled.
    - out_csv: Path to save the labeled output CSV file.
    - start_time: Start of the attack time window.
    - end_time: End of the attack time window.

    """
    new = read_csv(input_csv)
    new["Label"] = "Normal"

    mask = (
            (new["frame.time_relative"] > start_time) &
            (new["frame.time_relative"] < end_time) &
            ((new["ip.src"] == "85.75.109.194") | (new["ip.dst"] == "85.75.109.194")) &
            (new["quic.packet_length"].isnull())
    )

    new.loc[mask, "Label"] = "fuzzing"
    print(f"{input_csv.removesuffix('.csv')} -> samples for fuzzing: {np.sum(new['Label'] == 'fuzzing')}")
    new.to_csv(out_csv, index=False)


def http_loris_labeler(input_csv: str, out_csv: str, start_time: int, end_time: int) -> None:
    """
    Labels HTTP Loris slow-connection attack traffic within a time window,
    identified by traffic involving either of two known attack IPs and non-null UDP destination port.

   Inputs:
    - input_csv: Path to the raw input CSV file to be labeled.
    - out_csv: Path to save the labeled output CSV file.
    - start_time: Start of the attack time window.
    - end_time: End of the attack time window.

    """
    new = read_csv(input_csv)
    new["Label"] = "Normal"

    mask = (
            (new["frame.time_relative"] > start_time) &
            (new["frame.time_relative"] < end_time) &
            (
                    (new["ip.src"].isin(["85.75.109.194", "5.203.228.219"])) |
                    (new["ip.dst"].isin(["85.75.109.194", "5.203.228.219"]))
            ) &
            (new["udp.dstport"].notnull())
    )

    new.loc[mask, "Label"] = "http-loris"
    print(f"{input_csv.removesuffix('.csv')} -> samples for http-loris: {np.sum(new['Label'] == 'http-loris')}")
    new.to_csv(out_csv, index=False)


def http_stream_labeler(input_csv: str, out_csv: str, start_time_1: int, end_time_1: int, start_time_2: int,
                        end_time_2: int) -> None:
    """
    Labels HTTP stream attack traffic across two separate attack time windows per file,
    identified by attack IP and specific HTTP/3 QPACK table capacity values (409600 or 16).

    Inputs:
    - input_csv: Path to the raw input CSV file to be labeled.
    - out_csv: Path to save the labeled output CSV file.
    - start_time_1: Start of the first attack time window.
    - end_time_1: End of the first attack time window.
    - start_time_2: Start of the second attack time window.
    - end_time_2: End of the second attack time window.

    """
    new = read_csv(input_csv)
    new['Label'] = "Normal"

    mask = ((((new['frame.time_relative'] > start_time_1) & (new['frame.time_relative'] < end_time_1)) |
             ((new['frame.time_relative'] > start_time_2) & (new['frame.time_relative'] < end_time_2))) &
            (((new['ip.src'] == "85.75.109.194") | (new['ip.dst'] == "85.75.109.194")) &
             ((new['http3.settings.qpack.max_table_capacity'] == 409600) | (
                     new['http3.settings.qpack.max_table_capacity'] == 16))))

    new.loc[mask, "Label"] = "http-stream"
    print(f"{input_csv.removesuffix('.csv')} -> samples for http-stream: {np.sum(new['Label'] == 'http-stream')}")
    new.to_csv(out_csv, index=False)


def quic_flood_labeler(input_csv: str, out_csv: str, start_time: int, end_time: int) -> None:
    """
    Labels QUIC flood attack traffic within a time window from a specific attack IP,
    identified by non-null UDP destination port.

    Inputs:
    - input_csv: Path to the raw input CSV file to be labeled.
    - out_csv: Path to save the labeled output CSV file.
    - start_time: Start of the attack time window.
    - end_time: End of the attack time window.

    """
    new = read_csv(input_csv)
    new['Label'] = "Normal"

    mask = (
            (new["frame.time_relative"] > start_time) &
            (new["frame.time_relative"] < end_time) &
            ((new["ip.src"] == "85.75.109.194") | (new["ip.dst"] == "85.75.109.194")) &
            (new["udp.dstport"].notnull())
    )

    new.loc[mask, "Label"] = "quic-flood"
    print(f"{input_csv.removesuffix('.csv')} -> samples for quic-flood: {np.sum(new['Label'] == 'quic-flood')}")
    new.to_csv(out_csv, index=False)


def quic_loris_labeler(input_csv: str, out_csv: str, start_time: int, end_time: int) -> None:
    """
    Labels QUIC Loris slow-connection attack traffic within a time window,
    identified by traffic involving either of two known attack IPs and non-null UDP destination port.

    Inputs:
    - input_csv: Path to the raw input CSV file to be labeled.
    - out_csv: Path to save the labeled output CSV file.
    - start_time: Start of the attack time window.
    - end_time: End of the attack time window.

    """
    new = read_csv(input_csv)
    new["Label"] = "Normal"

    mask = (
            (new["frame.time_relative"] > start_time) &
            (new["frame.time_relative"] < end_time) &
            (
                    (new['ip.src'] == "85.75.109.194") | (new['ip.dst'] == "85.75.109.194") |
                    (new['ip.src'] == "5.203.228.219") | (new['ip.dst'] == "5.203.228.219")
            ) &
            (new["udp.dstport"].notnull())
    )

    new.loc[mask, "Label"] = "quic-loris"
    print(f"{input_csv.removesuffix('.csv')} -> samples for quic-loris: {np.sum(new['Label'] == 'quic-loris')}")
    new.to_csv(out_csv, index=False)


def quic_enc_labeler(input_csv: str, out_csv: str, start_time: int, end_time: int) -> None:
    """
    Labels QUIC encryption abuse attack traffic within a time window from a specific attack IP,
    identified by non-null DNS transaction ID (dns.id), indicating DNS-over-QUIC misuse.

    Inputs:
    - input_csv: Path to the raw input CSV file to be labeled.
    - out_csv: Path to save the labeled output CSV file.
    - start_time: Start of the attack time window.
    - end_time: End of the attack time window.

    """
    new = read_csv(input_csv)
    new['Label'] = "Normal"

    mask = (
            ((new['frame.time_relative'] > start_time) & (new['frame.time_relative'] < end_time)) & (
            ((new['ip.src'] == "85.75.109.194") | (new['ip.dst'] == "85.75.109.194")) & (
        new['dns.id'].notnull()))
    )

    new.loc[mask, "Label"] = "quic-enc"
    print(f"{input_csv.removesuffix('.csv')} -> samples for quic-enc: {np.sum(new['Label'] == 'quic-enc')}")
    new.to_csv(out_csv, index=False)


def http_smuggler_labeler(input_csv: str, out_csv: str, start_time: int, end_time: int) -> None:
    """
    Labels HTTP request smuggling attack traffic within a time window from a specific attack IP,
    identified by non-null URL-encoded form key (urlencoded-form.key).

    Inputs:
    - input_csv: Path to the raw input CSV file to be labeled.
    - out_csv: Path to save the labeled output CSV file.
    - start_time: Start of the attack time window.
    - end_time: End of the attack time window.

    """
    new = read_csv(input_csv)
    new['Label'] = "Normal"

    mask = (
            ((new['frame.time_relative'] > start_time) & (new['frame.time_relative'] < end_time)) & (
            ((new['ip.src'] == "85.75.109.194") | (new['ip.dst'] == "85.75.109.194")) & (
        new['urlencoded-form.key'].notnull()))
    )

    new.loc[mask, "Label"] = "http-smuggle"
    print(f"{input_csv.removesuffix('.csv')} -> samples for http-smuggle: {np.sum(new['Label'] == 'http-smuggle')}")
    new.to_csv(out_csv, index=False)


def http_concurrent_labeler(input_csv: str, out_csv: str, start_time: int, end_time: int, cond_control: str) -> None:
    """
    Labels HTTP/2 concurrent stream attack traffic within a time window from a specific attack IP.
    The distinguishing column varies per server type (http.host for HTTP/1 servers, http2.length for HTTP/2 servers).

    Inputs:
    - input_csv: Path to the raw input CSV file to be labeled.
    - out_csv: Path to save the labeled output CSV file.
    - start_time: Start of the attack time window.
    - end_time: End of the attack time window.
    - cond_control: Column name used to identify attack packets (either 'http.host' or 'http2.length').

    """
    new = read_csv(input_csv)
    new['Label'] = "Normal"

    mask = (
            ((new['frame.time_relative'] > start_time) & (new['frame.time_relative'] < end_time)) & (
            ((new['ip.src'] == "85.75.109.194") | (new['ip.dst'] == "85.75.109.194")) & (
        new[cond_control].notnull()))
    )

    new.loc[mask, "Label"] = "http2-concurrent"
    print(
        f"{input_csv.removesuffix('.csv')} -> samples for http2-concurrent: {np.sum(new['Label'] == 'http2-concurrent')}")
    new.to_csv(out_csv, index=False)


def http_pause_labeler(input_csv: str, out_csv: str, start_time: int, end_time: int | None, cond_control: str) -> None:
    """
    Labels HTTP/2 pause attack traffic within a time window from a specific attack IP.
    Supports open-ended time windows (no upper bound) by passing None as end_time.
    The distinguishing column varies per server type (http.host for HTTP/1 servers, http2.length for HTTP/2 servers).

    Inputs:
    - input_csv: Path to the raw input CSV file to be labeled.
    - out_csv: Path to save the labeled output CSV file.
    - start_time: Start of the attack time window.
    - end_time: End of the attack time window.
    - cond_control: Column name used to identify attack packets (either 'http.host' or 'http2.length').

    """
    new = read_csv(input_csv)
    new['Label'] = "Normal"

    time_check = (new['frame.time_relative'] > start_time)
    if end_time is not None:
        time_check = time_check & (new['frame.time_relative'] < end_time)

    mask = (
            time_check & (((new['ip.src'] == "85.75.109.194") | (new['ip.dst'] == "85.75.109.194")) &
             (new[cond_control].notnull()))
    )

    new.loc[mask, "Label"] = "http2-pause"
    print(f"{input_csv.removesuffix('.csv')} -> samples for http2-pause: {np.sum(new['Label'] == 'http2-pause')}")
    new.to_csv(out_csv, index=False)


# =====================================
# ---     Main Labeling Process     ---
# =====================================

def labeling():
    print("\n####### Labeling #######")
    print("Labeling dataset data...")
    # Att1
    os.chdir(os.path.join(ROOT_DIR, "1-http-flood"))
    http_flood_labeler("pcap1-litespeed.csv", "pcap1-litespeed-l.csv", 240, 300)
    http_flood_labeler("pcap1-caddy.csv", "pcap1-caddy-l.csv", 300, 360)
    http_flood_labeler("pcap1-nginx.csv", "pcap1-nginx-l.csv", 360, 420)
    http_flood_labeler("pcap1-windows.csv", "pcap1-windows-l.csv", 420, 480)
    http_flood_labeler("pcap1-cloudflare.csv", "pcap1-cloudflare-l.csv", 480, 540)
    http_flood_labeler("pcap1-h2o.csv", "pcap1-h2o-l.csv", 540, 600)

    # Att2
    os.chdir(os.path.join(ROOT_DIR, "2-fuzzing"))
    fuzzing_labeler("pcap2-litespeed.csv", "pcap2-litespeed-l.csv", 240, 300)
    fuzzing_labeler("pcap2-caddy.csv", "pcap2-caddy-l.csv", 300, 360)
    fuzzing_labeler("pcap2-nginx.csv", "pcap2-nginx-l.csv", 360, 420)
    fuzzing_labeler("pcap2-windows.csv", "pcap2-windows-l.csv", 420, 480)
    fuzzing_labeler("pcap2-cloudflare.csv", "pcap2-cloudflare-l.csv", 480, 540)
    fuzzing_labeler("pcap2-h2o.csv", "pcap2-h2o-l.csv", 540, 600)

    # Att3
    os.chdir(os.path.join(ROOT_DIR, "3-http-loris"))
    http_loris_labeler("pcap3-litespeed.csv", "pcap3-litespeed-l.csv", 240, 320)
    http_loris_labeler("pcap3-caddy.csv", "pcap3-caddy-l.csv", 300, 380)
    http_loris_labeler("pcap3-nginx.csv", "pcap3-nginx-l.csv", 360, 440)
    http_loris_labeler("pcap3-windows.csv", "pcap3-windows-l.csv", 420, 500)
    http_loris_labeler("pcap3-cloudflare.csv", "pcap3-cloudflare-l.csv", 480, 560)
    http_loris_labeler("pcap3-h2o.csv", "pcap3-h2o-l.csv", 540, 620)

    # Att4
    os.chdir(os.path.join(ROOT_DIR, "4-http-stream"))
    http_stream_labeler("pcap4-litespeed.csv", "pcap4-litespeed-l.csv", 240, 300, 780, 840)
    http_stream_labeler("pcap4-caddy.csv", "pcap4-caddy-l.csv", 300, 360, 840, 900)
    http_stream_labeler("pcap4-nginx.csv", "pcap4-nginx-l.csv", 360, 420, 900, 960)
    http_stream_labeler("pcap4-windows.csv", "pcap4-windows-l.csv", 420, 480, 960, 1020)
    http_stream_labeler("pcap4-cloudflare.csv", "pcap4-cloudflare-l.csv", 480, 540, 1020, 1080)
    http_stream_labeler("pcap4-h2o.csv", "pcap4-h2o-l.csv", 540, 600, 1080, 1140)

    # Att5
    os.chdir(os.path.join(ROOT_DIR, '5-quic-flood'))
    quic_flood_labeler("pcap5-litespeed.csv", "pcap5-litespeed-l.csv", 240, 300)
    quic_flood_labeler("pcap5-caddy.csv", "pcap5-caddy-l.csv", 300, 360)
    quic_flood_labeler("pcap5-nginx.csv", "pcap5-nginx-l.csv", 360, 420)
    quic_flood_labeler("pcap5-windows.csv", "pcap5-windows-l.csv", 420, 480)
    quic_flood_labeler("pcap5-cloudflare.csv", "pcap5-cloudflare-l.csv", 480, 540)
    quic_flood_labeler("pcap5-h2o.csv", "pcap5-h2o-l.csv", 540, 600)

    # Att6
    os.chdir(os.path.join(ROOT_DIR, "6-quic-loris"))
    quic_loris_labeler("pcap6-litespeed.csv", "pcap6-litespeed-l.csv", 240, 320)
    quic_loris_labeler("pcap6-caddy.csv", "pcap6-caddy-l.csv", 300, 380)
    quic_loris_labeler("pcap6-nginx.csv", "pcap6-nginx-l.csv", 360, 440)
    quic_loris_labeler("pcap6-windows.csv", "pcap6-windows-l.csv", 420, 500)
    quic_loris_labeler("pcap6-cloudflare.csv", "pcap6-cloudflare-l.csv", 480, 560)
    quic_loris_labeler("pcap6-h2o.csv", "pcap6-h2o-l.csv", 540, 620)

    # Att7
    os.chdir(os.path.join(ROOT_DIR, '7-quic-enc'))
    quic_enc_labeler("pcap7-litespeed.csv", "pcap7-litespeed-l.csv", 240, 300)
    quic_enc_labeler("pcap7-caddy.csv", "pcap7-caddy-l.csv", 300, 360)
    quic_enc_labeler("pcap7-nginx.csv", "pcap7-nginx-l.csv", 360, 420)
    quic_enc_labeler("pcap7-windows.csv", "pcap7-windows-l.csv", 420, 480)
    quic_enc_labeler("pcap7-cloudflare.csv", "pcap7-cloudflare-l.csv", 480, 540)
    quic_enc_labeler("pcap7-h2o.csv", "pcap7-h2o-l.csv", 540, 600)

    # Att8
    os.chdir(os.path.join(ROOT_DIR, '8-http-smuggle'))
    http_smuggler_labeler("pcap8-litespeed.csv", "pcap8-litespeed-l.csv", 180, 300)
    http_smuggler_labeler("pcap8-caddy.csv", "pcap8-caddy-l.csv", 300, 420)
    http_smuggler_labeler("pcap8-nginx.csv", "pcap8-nginx-l.csv", 420, 540)
    http_smuggler_labeler("pcap8-windows.csv", "pcap8-windows-l.csv", 540, 660)
    http_smuggler_labeler("pcap8-cloudflare.csv", "pcap8-cloudflare-l.csv", 660, 780)
    http_smuggler_labeler("pcap8-h2o.csv", "pcap8-h2o-l.csv", 780, 900)

    # Att9
    os.chdir(os.path.join(ROOT_DIR, '9-http2-concurrent'))
    http_concurrent_labeler("pcap9-litespeed.csv", "pcap9-litespeed-l.csv", 180, 210, "http.host")
    http_concurrent_labeler("pcap9-caddy.csv", "pcap9-caddy-l.csv", 210, 240, "http2.length")
    http_concurrent_labeler("pcap9-nginx.csv", "pcap9-nginx-l.csv", 240, 270, "http.host")
    http_concurrent_labeler("pcap9-windows.csv", "pcap9-windows-l.csv", 270, 300, "http2.length")
    http_concurrent_labeler("pcap9-cloudflare.csv", "pcap9-cloudflare-l.csv", 300, 330, "http.host")
    http_concurrent_labeler("pcap9-h2o.csv", "pcap9-h2o-l.csv", 330, 360, "http2.length")

    # Att10
    os.chdir(os.path.join(ROOT_DIR, "10-http2-pause"))
    http_pause_labeler("pcap10-litespeed.csv", "pcap10-litespeed-l.csv", 180, 210, "http.host")
    http_pause_labeler("pcap10-caddy.csv", "pcap10-caddy-l.csv", 210, 240, "http2.length")
    http_pause_labeler("pcap10-nginx.csv", "pcap10-nginx-l.csv", 240, 270, "http.host")
    http_pause_labeler("pcap10-windows.csv", "pcap10-windows-l.csv", 270, 300, "http2.length")
    http_pause_labeler("pcap10-cloudflare.csv", "pcap10-cloudflare-l.csv", 300, 330, "http.host")
    http_pause_labeler("pcap10-h2o.csv", "pcap10-h2o-l.csv", 330, None, "http2.length")

    print("Labeling Complete!\n")
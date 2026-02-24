import pandas as pd
from termcolor import cprint
import os
import glob
from pathlib import Path

DATASET_DIR = os.path.join(Path(__file__).resolve().parent.parent, "dataset")
OUTPUT_DIR = os.path.join(Path(__file__).resolve().parent.parent, "output")

FEATURES = [
    "frame.len", "ip.len", "tcp.len", "tcp.hdr_len", "tcp.flags.ack",
    "tcp.flags.push", "tcp.flags.reset", "tcp.flags.syn", "tcp.flags.fin",
    "tcp.window_size_value", "tcp.option_len", "udp.length", "tls.record.length",
    "tls.reassembled.length", "tls.handshake.length", "tls.handshake.certificates_length",
    "tls.handshake.certificate_length", "tls.handshake.session_id_length",
    "tls.handshake.cipher_suites_length", "tls.handshake.extensions_length",
    "tls.handshake.client_cert_vrfy.sig_len", "quic.packet_length", "quic.long.packet_type",
    "quic.packet_number_length", "quic.length", "quic.nci.connection_id.length",
    "quic.crypto.length", "quic.fixed_bit", "quic.spin_bit", "quic.stream.fin",
    "quic.stream.len", "quic.token_length", "quic.padding_length", "http2.length",
    "http2.header.length", "http2.header.name.length", "http2.header.value.length",
    "http2.headers.content_length", "http3.frame_length",
    "http3.settings.qpack.max_table_capacity", "http3.settings.max_field_section_size",
    "dns.flags.response", "dns.count.queries", "dns.count.answers",
    "http.content_length", "http.content_type", "Label"
]


# =====================================
# ---  Filtering Helper Functions   ---
# =====================================

def merge_and_filter_data(csv_files: list) -> pd.DataFrame:
    """
    Reads and merges multiple CSV files into a single DataFrame,
    keeping only the features defined in the FEATURES list.

    Input:
    - csv_files: List of file paths to the labeled CSV files to be processed.

    Output:
    - merged_data: A single merged DataFrame containing only the selected feature columns.
    """
    merged_data = pd.DataFrame()
    for i, fileName in enumerate(csv_files):
        cprint(f"Progress: {i + 1}/{len(csv_files)} - {os.path.basename(fileName)}", "green")
        data = pd.read_csv(fileName, sep=',', on_bad_lines='skip', low_memory=False)
        new = data.filter(FEATURES)
        merged_data = pd.concat([merged_data, new], ignore_index=True)

    cprint("Finished reading all files. Saving merged CSV...")
    return merged_data


def save_merged_csv(data: pd.DataFrame) -> str:
    """
    Saves a DataFrame to a CSV file in the output directory,
    creating the directory if it does not exist.

    Input:
    - data: The merged and filtered DataFrame to be saved.

    Output:
    - output_path: The full file path where the CSV was saved.

    """
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    output_path = os.path.join(OUTPUT_DIR, "pcap-all.csv")
    data.to_csv(output_path, index=False)
    print("Saved merged file to:", output_path)
    return output_path


# =====================================
# ---   Main Filtering Process      ---
# =====================================

def filtering() -> str:
    print("\n####### Filtering #######")

    print("Looking for CSV files in:", DATASET_DIR)
    csv_files = glob.glob(os.path.join(DATASET_DIR, "**", "*-l.csv"),
                          recursive=True)  # labeled csvs are marked with '-l'

    print(f"Found {len(csv_files)} CSV file(s):")
    for file in csv_files:
        print(f"\t - {file}")

    print("\nFiltering dataset data...")
    data = merge_and_filter_data(csv_files)
    print("Filtering Complete!\n")
    return save_merged_csv(data)

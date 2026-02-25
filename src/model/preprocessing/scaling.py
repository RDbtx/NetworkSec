import sys
import os
from sklearn.preprocessing import MinMaxScaler
import pandas as pd

# Columns that are categorical/flags -> fill NaN with -1 then One-Hot Encode
FLAG_COLS = [
    'tcp.flags.ack', 'tcp.flags.push', 'tcp.flags.reset', 'tcp.flags.syn', 'tcp.flags.fin',
    'quic.long.packet_type', 'quic.fixed_bit', 'quic.spin_bit',
    'quic.stream.fin', 'dns.flags.response', 'http.content_type'
]

# Numeric columns to MinMax scale
TO_SCALE_COLUMNS = [
    "frame.len", "ip.len", "tcp.len", "tcp.hdr_len", "tcp.window_size_value",
    "tcp.option_len", "udp.length", "tls.record.length", "tls.reassembled.length",
    "tls.handshake.length", "tls.handshake.certificates_length", "tls.handshake.certificate_length",
    "tls.handshake.session_id_length", "tls.handshake.cipher_suites_length",
    "tls.handshake.extensions_length", "tls.handshake.client_cert_vrfy.sig_len",
    "quic.packet_length", "quic.packet_number_length", "quic.length",
    "quic.nci.connection_id.length", "quic.crypto.length", "quic.stream.len",
    "quic.token_length", "quic.padding_length", "http2.length", "http2.header.length",
    "http2.header.name.length", "http2.header.value.length", "http2.headers.content_length",
    "http3.frame_length", "http3.settings.qpack.max_table_capacity",
    "http3.settings.max_field_section_size", "dns.count.queries", "dns.count.answers",
    "http.content_length"
]


# =====================================
# ---   Scaling Helper Functions    ---
# =====================================

def fill_missing_values(df: pd.DataFrame) -> pd.DataFrame:
    """
    Fills NaN values: FLAG_COLS get -1 (to preserve them as a distinct category before OHE),
    all remaining NaN cells are filled with 0.

    Input:
    - df: The input DataFrame with potential NaN values.

    Output:
    - df (pd.DataFrame): DataFrame with all NaN values filled.

    """
    print("Filling missing values...\n")
    for col in FLAG_COLS:
        df[col] = df[col].fillna(-1)
    df = df.fillna(0)
    print("Done filling NaN cells!")
    return df


def resolve_compound_values(df: pd.DataFrame) -> pd.DataFrame:
    """
    Evaluates string-encoded arithmetic expressions in object-type columns.

    Input:
    - df: DataFrame potentially containing string arithmetic in object columns.

    Output:
    - df: DataFrame with all compound string values resolved to numeric.
    """
    sys.setrecursionlimit(5000)
    print("Started resolving compound values...")
    obj_cols = [c for c in df.select_dtypes(include="object").columns if c != "Label"]
    total = len(obj_cols)
    for i, col in enumerate(obj_cols, start=1):
        try:
            df[col] = df[col].apply(lambda v: pd.eval(v) if isinstance(v, str) else v)
        except Exception:
            pass
        print(f" - [{i}/{total}] Done calculations in {col}")
    print("Done resolving all compound values!")
    return df


def one_hot_encode(df: pd.DataFrame) -> pd.DataFrame:
    """
    Applies One-Hot Encoding to all FLAG_COLS, expanding each into binary indicator columns.

    Input:
    - df: DataFrame containing the flag/categorical columns to encode.

    Outputs:
    - df: DataFrame with FLAG_COLS replaced by their OHE binary columns.
    """
    print("Starting One-Hot Encoding...\n")
    df = pd.get_dummies(df, columns=FLAG_COLS)
    print("Done One-Hot Encoding!")
    return df


def minmax_scale(df: pd.DataFrame) -> pd.DataFrame:
    """
    Applies MinMax normalization to all TO_SCALE_COLUMNS, scaling values to the [0, 1] range.
    Moves the Label column back to the last position after scaling.

    Input:
    - df: DataFrame containing the numeric columns to scale.

    Output:
    - df: DataFrame with TO_SCALE_COLUMNS normalized and Label as last column.
    """
    print("Starting MinMax Scaling...\n")
    scaler = MinMaxScaler()
    df[TO_SCALE_COLUMNS] = df[TO_SCALE_COLUMNS].astype(float)
    df[TO_SCALE_COLUMNS] = scaler.fit_transform(df[TO_SCALE_COLUMNS])
    df.insert(len(df.columns) - 1, "Label", df.pop("Label"))
    print("Done MinMax scaling!")
    return df


# =====================================
# ---      Main Scaling Process     ---
# =====================================

def scaling(csv_dir: str) -> None:
    """
    reads the merged CSV, fills NaN values, resolves compound
    string values, applies OHE to flag columns, applies MinMax scaling to numeric columns,
    and saves the final classification-ready CSV.

    Input:
    - csv_dir: Path to the merged input CSV file (pcap-all.csv).

    """
    print("\n####### Scaling #######")
    output_path = os.path.join(os.path.dirname(csv_dir), "pcap-all-final.csv")

    print("Reading:", csv_dir)
    df = pd.read_csv(csv_dir, sep=",", on_bad_lines='skip', encoding="ISO-8859-1", low_memory=False)
    print("Done reading CSV!")

    df = fill_missing_values(df)
    df = resolve_compound_values(df)
    df = one_hot_encode(df)
    df = minmax_scale(df)

    df.to_csv(output_path, index=False)
    print("Scaling Complete!\n")

import os
import glob
import subprocess
import pandas as pd
import pathlib
import shutil

ROOT_FOLDER = pathlib.Path(__file__).parent.parent

# ── CONFIGURE THESE ──────────────────────────────────────────────────────────
DATASET_FOLDER    = str(ROOT_FOLDER / "src/model/dataset")
OUTPUT_FOLDER     = str(ROOT_FOLDER / "attacks/attack_pcaps/")
REWRITTEN_FOLDER  = str(ROOT_FOLDER / "attacks/attack_pcaps_rewritten/")
INTERFACE         = "lo0"
MULTIPLIER        = 5
MAX_FRAMES        = 5000   # max attack frames per label total — set to None for all
# ─────────────────────────────────────────────────────────────────────────────

# maps each raw label to the dataset subfolder that contains its pcaps
LABEL_FOLDERS = {
    "http-flood":       "1-http-flood",
    "fuzzing":          "2-fuzzing",
    "http-loris":       "3-http-loris",
    # no http stream since no samples were found
    "quic-flood":       "5-quic-flood",
    "quic-loris":       "6-quic-loris",
    "quic-enc":         "7-quic-enc",
    "http-smuggle":     "8-http-smuggle",
    "http2-concurrent": "9-http2-concurrent",
    "http2-pause":      "10-http2-pause",
}

ATTACK_LABELS = list(LABEL_FOLDERS.keys())


def find_pairs_for_label(dataset_folder: str, label: str):
    """Find pcap+csv pairs only inside the folder mapped to this label."""
    subfolder = os.path.join(dataset_folder, LABEL_FOLDERS[label])
    if not os.path.isdir(subfolder):
        print(f"  [WARN] Folder not found: {subfolder}")
        return []
    pairs = []
    pcap_files = (glob.glob(os.path.join(subfolder, "*.pcap")) +
                  glob.glob(os.path.join(subfolder, "*.pcapng")))
    for pcap in sorted(pcap_files):
        base = pcap.rsplit(".", 1)[0]
        labeled_csv = base + "-l.csv"
        if os.path.exists(labeled_csv):
            pairs.append((pcap, labeled_csv))
        else:
            print(f"  [WARN] No labeled CSV for {os.path.basename(pcap)}, skipping.")
    return pairs


def get_frames_for_label(labeled_csv: str, label: str) -> list:
    """Return 1-based frame numbers for a specific label in this CSV."""
    df = pd.read_csv(labeled_csv, low_memory=False)
    if "Label" not in df.columns:
        return []
    return (df.index[df["Label"] == label] + 1).tolist()


def frames_to_ranges(frame_numbers: list) -> list:
    """Convert sorted frame numbers to editcap range strings e.g. [1,2,3,5] -> ['1-3','5']"""
    if not frame_numbers:
        return []
    ranges = []
    start = prev = frame_numbers[0]
    for n in frame_numbers[1:]:
        if n == prev + 1:
            prev = n
        else:
            ranges.append(f"{start}-{prev}" if start != prev else str(start))
            start = prev = n
    ranges.append(f"{start}-{prev}" if start != prev else str(start))
    return ranges


def extract_frames(pcap: str, frame_numbers: list, out_pcap: str) -> bool:
    """Extract frames using editcap range notation, batching by 500 ranges."""
    os.makedirs(os.path.dirname(out_pcap), exist_ok=True)
    ranges = frames_to_ranges(sorted(frame_numbers))
    BATCH = 500
    batches = [ranges[i:i+BATCH] for i in range(0, len(ranges), BATCH)]

    if len(batches) == 1:
        result = subprocess.run(
            ["editcap", "-r", pcap, out_pcap] + batches[0],
            capture_output=True, text=True
        )
        if result.returncode != 0:
            print(f"      [ERROR] editcap failed: {result.stderr.strip()}")
            return False
        return True

    tmp_batch_dir = out_pcap + "_batches"
    os.makedirs(tmp_batch_dir, exist_ok=True)
    batch_files = []
    for idx, batch in enumerate(batches):
        batch_out = os.path.join(tmp_batch_dir, f"batch_{idx:04d}.pcap")
        result = subprocess.run(
            ["editcap", "-r", pcap, batch_out] + batch,
            capture_output=True, text=True
        )
        if result.returncode == 0:
            batch_files.append(batch_out)

    if not batch_files:
        shutil.rmtree(tmp_batch_dir, ignore_errors=True)
        return False

    if len(batch_files) == 1:
        shutil.move(batch_files[0], out_pcap)
    else:
        result = subprocess.run(
            ["mergecap", "-w", out_pcap] + batch_files,
            capture_output=True, text=True
        )
        if result.returncode != 0:
            shutil.rmtree(tmp_batch_dir, ignore_errors=True)
            return False

    shutil.rmtree(tmp_batch_dir, ignore_errors=True)
    return True


def merge_pcaps(input_pcaps: list, out_pcap: str) -> bool:
    os.makedirs(os.path.dirname(out_pcap), exist_ok=True)
    result = subprocess.run(
        ["mergecap", "-w", out_pcap] + input_pcaps,
        capture_output=True, text=True
    )
    if result.returncode != 0:
        print(f"  [ERROR] mergecap failed: {result.stderr.strip()}")
        return False
    return True


if __name__ == "__main__":
    print(f"\n=== Extracting Attack PCAPs divided by label ===")
    print(f"Dataset    : {DATASET_FOLDER}")
    print(f"Output     : {OUTPUT_FOLDER}")
    print(f"Max frames : {MAX_FRAMES if MAX_FRAMES else 'all'}\n")

    os.makedirs(OUTPUT_FOLDER, exist_ok=True)
    tmp_dir = os.path.join(OUTPUT_FOLDER, "_tmp")
    os.makedirs(tmp_dir, exist_ok=True)

    final_pcaps = []

    # ── iterate by label ──────────────────────────────────────────────────────
    for label in ATTACK_LABELS:
        print(f"Processing: [{label}]")
        collected = []
        total_frames = 0

        pairs = find_pairs_for_label(DATASET_FOLDER, label)
        if not pairs:
            print(f"  No pcap+csv pairs found for [{label}], skipping.\n")
            continue

        for pcap, labeled_csv in pairs:
            if MAX_FRAMES is not None and total_frames >= MAX_FRAMES:
                print(f"  MAX_FRAMES={MAX_FRAMES} reached — skipping remaining files.")
                break

            frames = get_frames_for_label(labeled_csv, label)
            if not frames:
                continue

            # trim to remaining budget if needed
            if MAX_FRAMES is not None:
                remaining = MAX_FRAMES - total_frames
                frames = frames[:remaining]

            pcap_name = os.path.basename(pcap).replace(".pcap", "").replace(".pcapng", "")
            tmp_out   = os.path.join(tmp_dir, f"{label}__{pcap_name}.pcap")
            print(f"  {pcap_name}: {len(frames)} frames → {os.path.basename(tmp_out)}")

            if extract_frames(pcap, frames, tmp_out):
                collected.append(tmp_out)
                total_frames += len(frames)

        if not collected:
            print(f"  No frames found for [{label}], skipping.\n")
            continue

        print(f"  Total: {total_frames} frames across {len(collected)} file(s)")

        final_path = os.path.join(OUTPUT_FOLDER, f"{label}.pcap")
        if len(collected) == 1:
            shutil.copy(collected[0], final_path)
            final_pcaps.append(final_path)
        else:
            print(f"  Merging {len(collected)} files → {label}.pcap")
            if merge_pcaps(collected, final_path):
                final_pcaps.append(final_path)
            else:
                print(f"  [ERROR] Merge failed for [{label}]")
        print()

    shutil.rmtree(tmp_dir, ignore_errors=True)

    print(f"=== Output files in {OUTPUT_FOLDER} ===")
    for f in sorted(os.listdir(OUTPUT_FOLDER)):
        fpath = os.path.join(OUTPUT_FOLDER, f)
        size_mb = os.path.getsize(fpath) / 1024 / 1024
        print(f"  {f:<35} {size_mb:.1f} MB")

    # ── rewrite destination IPs to 127.0.0.1 ─────────────────────────────────
    print(f"\n=== Rewriting destination IPs → 127.0.0.1 ===")
    os.makedirs(REWRITTEN_FOLDER, exist_ok=True)
    rewritten_pcaps = []

    for f in sorted(final_pcaps):
        rw_path = os.path.join(REWRITTEN_FOLDER, os.path.basename(f))
        print(f"  {os.path.basename(f)} → {REWRITTEN_FOLDER}")
        result = subprocess.run([
            "tcprewrite",
            f"--infile={f}",
            f"--outfile={rw_path}",
            "--dstipmap=0.0.0.0/0:127.0.0.1",
        ], capture_output=True, text=True)
        if result.returncode != 0:
            print(f"  [ERROR] tcprewrite failed: {result.stderr.strip()}")
        else:
            rewritten_pcaps.append(rw_path)

    print(f"\n=== Rewritten files in {REWRITTEN_FOLDER} ===")
    for f in sorted(os.listdir(REWRITTEN_FOLDER)):
        fpath = os.path.join(REWRITTEN_FOLDER, f)
        size_mb = os.path.getsize(fpath) / 1024 / 1024
        print(f"  {f:<35} {size_mb:.1f} MB")

    print(f"\n=== To replay an attack ===")
    for f in sorted(rewritten_pcaps):
        print(f"  sudo tcpreplay --intf1={INTERFACE} --multiplier={MULTIPLIER} {f}")
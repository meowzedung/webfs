import os
import sys
import json
import shutil
import secrets
import string
import hashlib
import argparse
from collections import defaultdict

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

# CONSTANTS & CONFIGURATION
BLOB_SIZE = 32 * 1024 * 1024
INDEX_SIZE = 16 * 1024
INDEX_OFFSET = BLOB_SIZE - INDEX_SIZE

SALT_LEN = 16
IV_LEN = 12
GC_THRESHOLD = 0.75 # 75% dead space in a single blob triggers compaction

def hash_file(filepath: str) -> str:
    sha256 = hashlib.sha256()
    with open(filepath, "rb") as f:
        while chunk := f.read(8192):
            sha256.update(chunk)
    return sha256.hexdigest()

def group_files_by_password(root_dir: str) -> dict:
    print(f"[*] Scanning directory: '{root_dir}' for '.passwd' rules...")
    passwd_file = os.path.join(root_dir, ".passwd")
    rules = {}

    if os.path.exists(passwd_file):
        with open(passwd_file, "r") as file_obj:
            for line in file_obj:
                line = line.strip()
                if not line or line.startswith("#"): continue
                path, password = line.split(None, 1)
                path = path.rstrip("/")
                rules["." if path == "." else os.path.normpath(path)] = password
    else:
        print("[!] No '.passwd' file found. All files will need a default rule.")

    def resolve_password(rel_path: str) -> str:
        path = os.path.normpath(rel_path)
        while True:
            if path in rules: return rules[path]
            if path == "." or path == "": return rules.get(".", None)
            path = os.path.dirname(path)

    groups = defaultdict(list)
    for root, _, files in os.walk(root_dir):
        for name in files:
            if name == ".passwd": continue
            full_path = os.path.join(root, name)
            rel_path = os.path.relpath(full_path, root_dir)
            rel_dir = os.path.dirname(rel_path) or "."

            password = resolve_password(rel_dir)
            if not password: continue
            groups[password].append(rel_path)

    return dict(groups)

def generate_random_blob_name() -> str:
    alphabet = string.ascii_letters + string.digits
    return ''.join(secrets.choice(alphabet) for _ in range(12))

def derive_encryption_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=200000)
    return kdf.derive(password.encode())

def create_new_blob(blob_dir: str):
    blob_name = generate_random_blob_name()
    blob_path = os.path.join(blob_dir, blob_name)
    blob_file = open(blob_path, "wb+")
    blob_file.truncate(BLOB_SIZE)
    return blob_file, blob_name

def try_decrypt_index(blob_path: str, password: str):
    try:
        with open(blob_path, "rb") as blob_file:
            blob_file.seek(INDEX_OFFSET)
            region = blob_file.read(INDEX_SIZE)

        if len(region) < 32: return None
        salt, iv = region[:16], region[16:28]
        length = int.from_bytes(region[28:32], byteorder="big")
        ciphertext = region[32 : 32 + length]

        key = derive_encryption_key(password, salt)
        cipher = AESGCM(key)
        plaintext = cipher.decrypt(iv, ciphertext, associated_data=None)
        return json.loads(plaintext.decode('utf-8')), salt, key
    except Exception:
        return None

def find_current_state(blob_dir: str, password: str):
    if not os.path.exists(blob_dir): return None, None, None, None
    for filename in os.listdir(blob_dir):
        if filename.endswith(".json"): continue
        res = try_decrypt_index(os.path.join(blob_dir, filename), password)
        if res: return res[0], filename, res[1], res[2]
    return None, None, None, None

def write_index(blob_file, index_dict, group_salt, group_key):
    print(index_dict)
    index_json_bytes = json.dumps(index_dict).encode()
    cipher = AESGCM(group_key)
    index_iv = secrets.token_bytes(IV_LEN)
    index_ciphertext = cipher.encrypt(index_iv, index_json_bytes, associated_data=None)

    payload = group_salt + index_iv + len(index_ciphertext).to_bytes(4, byteorder="big") + index_ciphertext

    blob_file.seek(INDEX_OFFSET)
    blob_file.write(payload)

def write_raw_bytes_to_blobs(raw_data, blob_dir, active_blob_file, active_blob_name, write_cursor, index_dict):
    """Core logic to split any raw byte sequence across blobs and log the chunks."""
    payload_offset = 0
    new_chunks = []

    while payload_offset < len(raw_data):
        remaining_blob_space = INDEX_OFFSET - write_cursor
        chunk_size = min(remaining_blob_space, len(raw_data) - payload_offset)

        start_byte = write_cursor
        end_byte = write_cursor + chunk_size - 1

        active_blob_file.seek(write_cursor)
        active_blob_file.write(raw_data[payload_offset : payload_offset + chunk_size])

        new_chunks.append([active_blob_name, start_byte, end_byte])

        if active_blob_name not in index_dict["blob_stats"]:
            index_dict["blob_stats"][active_blob_name] = {"live_bytes": 0, "dead_bytes": 0}
        index_dict["blob_stats"][active_blob_name]["live_bytes"] += chunk_size

        write_cursor += chunk_size
        payload_offset += chunk_size

        if write_cursor == INDEX_OFFSET:
            active_blob_file.close()
            active_blob_file, active_blob_name = create_new_blob(blob_dir)
            write_cursor = 0

    return active_blob_file, active_blob_name, write_cursor, new_chunks

def pack_group_full(root_dir, password, files, blob_dir):
    print(f"\n[+] Doing FULL REPACK for group ({len(files)} files)...")
    group_salt = secrets.token_bytes(SALT_LEN)
    group_key = derive_encryption_key(password, group_salt)

    active_blob_file, active_blob = create_new_blob(blob_dir)
    write_cursor = 0
    index_dict = {"files": {}, "blob_stats": {}}
    cipher = AESGCM(group_key)

    for filename in files:
        print(f"    -> Encrypting: {filename}")
        filepath = os.path.join(root_dir, filename)
        f_hash, f_size = hash_file(filepath), os.path.getsize(filepath)

        with open(filepath, "rb") as target_file:
            raw_data = target_file.read()

        file_iv = secrets.token_bytes(IV_LEN)
        ciphertext = cipher.encrypt(file_iv, raw_data, associated_data=None)
        encrypted_payload = group_salt + file_iv + ciphertext

        index_dict["files"][filename] = {"hash": f_hash, "size": f_size, "chunks": []}
        active_blob_file, active_blob, write_cursor, chunks = write_raw_bytes_to_blobs(
            encrypted_payload, blob_dir, active_blob_file, active_blob, write_cursor, index_dict
        )
        index_dict["files"][filename]["chunks"] = chunks

    print(f"[*] Finalizing. Writing index to: {active_blob}")
    write_index(active_blob_file, index_dict, group_salt, group_key)
    active_blob_file.close()

def append_group(root_dir, password, local_files, blob_dir):
    index_dict, active_blob, group_salt, group_key = find_current_state(blob_dir, password)

    if not index_dict:
        print("\n[!] No existing index found for this password. Defaulting to full repack.")
        pack_group_full(root_dir, password, local_files, blob_dir)
        return

    print(f"\n[+] Scanning for changes (Hashing)...")
    index_files = index_dict.get("files", {})
    blob_stats = index_dict.get("blob_stats", {})

    to_add, to_modify, to_delete = [], [], []

    for filename in local_files:
        filepath = os.path.join(root_dir, filename)
        f_hash, f_size = hash_file(filepath), os.path.getsize(filepath)

        if filename not in index_files:
            to_add.append((filename, f_hash, f_size))
        elif index_files[filename]["hash"] != f_hash:
            to_modify.append((filename, f_hash, f_size))

    for filename in list(index_files.keys()):
        if filename not in local_files:
            to_delete.append(filename)

    # Tombstone old data for modified/deleted files
    for filename in [f[0] for f in to_modify] + to_delete:
        for b_name, start, end in index_files[filename]["chunks"]:
            chunk_size = end - start + 1
            blob_stats[b_name]["dead_bytes"] += chunk_size
            blob_stats[b_name]["live_bytes"] -= chunk_size
        del index_files[filename]

    # --- COMPACTION & GC PHASE ---
    blobs_to_compact = []
    for b_name, stats in blob_stats.items():
        total_written = stats["live_bytes"] + stats["dead_bytes"]
        if total_written > 0 and (stats["dead_bytes"] / total_written) >= GC_THRESHOLD:
            blobs_to_compact.append(b_name)

    write_cursor = 0
    for f_info in index_files.values():
        for b_name, start, end in f_info.get("chunks", []):
            if b_name == active_blob:
                write_cursor = max(write_cursor, end + 1)

    active_blob_file = open(os.path.join(blob_dir, active_blob), "r+b")

    # If the active blob itself needs compaction, roll it over first.
    if active_blob in blobs_to_compact:
        print(f"[*] Active blob '{active_blob}' marked for compaction. Rolling over...")
        active_blob_file.close()
        active_blob_file, active_blob = create_new_blob(blob_dir)
        write_cursor = 0

    # Execute Compaction (Moving raw bytes)
    for bad_blob in blobs_to_compact:
        dead_pct = (blob_stats[bad_blob]["dead_bytes"] / (blob_stats[bad_blob]["live_bytes"] + blob_stats[bad_blob]["dead_bytes"])) * 100
        print(f"[*] Compacting blob '{bad_blob}' ({dead_pct:.1f}% dead space). Shifting live data...")

        with open(os.path.join(blob_dir, bad_blob), "rb") as f_in:
            for filename, file_info in index_files.items():
                new_chunks = []
                for chunk in file_info["chunks"]:
                    if chunk[0] == bad_blob:
                        # Read raw encrypted chunk from dead blob
                        f_in.seek(chunk[1])
                        raw_chunk_bytes = f_in.read(chunk[2] - chunk[1] + 1)

                        # Copy seamlessly to active blob
                        active_blob_file, active_blob, write_cursor, gen_chunks = write_raw_bytes_to_blobs(
                            raw_chunk_bytes, blob_dir, active_blob_file, active_blob, write_cursor, index_dict
                        )
                        new_chunks.extend(gen_chunks)
                    else:
                        new_chunks.append(chunk)
                file_info["chunks"] = new_chunks

        del index_dict["blob_stats"][bad_blob]
        os.remove(os.path.join(blob_dir, bad_blob))

    # --- APPEND NEW DATA PHASE ---
    if not to_add and not to_modify and not to_delete and not blobs_to_compact:
        print("[*] Group is completely up to date. No changes made.")
        active_blob_file.close()
        return

    print(f"[*] Appending {len(to_add)} new, {len(to_modify)} modified. Abandoning {len(to_delete)} deleted.")
    cipher = AESGCM(group_key)

    for filename, f_hash, f_size in to_add + to_modify:
        print(f"    -> Encrypting new data: {filename}")
        filepath = os.path.join(root_dir, filename)
        with open(filepath, "rb") as target_file:
            raw_data = target_file.read()

        file_iv = secrets.token_bytes(IV_LEN)
        ciphertext = cipher.encrypt(file_iv, raw_data, associated_data=None)
        encrypted_payload = group_salt + file_iv + ciphertext

        index_dict["files"][filename] = {"hash": f_hash, "size": f_size, "chunks": []}
        active_blob_file, active_blob, write_cursor, chunks = write_raw_bytes_to_blobs(
            encrypted_payload, blob_dir, active_blob_file, active_blob, write_cursor, index_dict
        )
        index_dict["files"][filename]["chunks"] = chunks

    print(f"[*] Finalizing. Writing updated index to: {active_blob}")
    write_index(active_blob_file, index_dict, group_salt, group_key)
    active_blob_file.close()

def update_global_manifest(blob_dir):
    blobs = [f for f in os.listdir(blob_dir) if not f.endswith(".json")]
    manifest_path = os.path.join(blob_dir, "blobs.json")
    with open(manifest_path, "w") as manifest_file:
        json.dump(blobs, manifest_file)
    print(f"\n[*] Global manifest updated. Total active blobs: {len(blobs)}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="WebFS Packer")
    parser.add_argument("input_dir", help="Directory to pack")
    parser.add_argument("-a", "--append", action="store_true", help="Append changes only (uses hashes & compaction)")
    args = parser.parse_args()

    print("========================================")
    print(f"   WebFS Packer {'(APPEND MODE)' if args.append else '(FULL MODE)'}")
    print("========================================")

    blob_dir = "blobs"
    if not args.append:
        if os.path.isdir(blob_dir):
            print(f"[*] Full run triggered. Wiping '{blob_dir}'...")
            shutil.rmtree(blob_dir)
    os.makedirs(blob_dir, exist_ok=True)

    password_groups = group_files_by_password(args.input_dir)

    for password, files in password_groups.items():
        if args.append:
            append_group(args.input_dir, password, files, blob_dir)
        else:
            pack_group_full(args.input_dir, password, files, blob_dir)

    update_global_manifest(blob_dir)
    print("\n========================================")
    print("        Process Completed Successfully  ")
    print("========================================")
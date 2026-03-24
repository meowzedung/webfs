import os
import sys
import json
import shutil
import secrets
import string
from collections import defaultdict
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

# CONSTANTS & CONFIGURATION
BLOB_SIZE = 32 * 1024 * 1024       # 32 MB fixed blob size
MAX_FILE_SIZE = 127 * 1024 * 1024  # 127 MB (Unused directly, but good for reference)
INDEX_SIZE = 16 * 1024             # 16 KB reserved for the index at the end of a blob
INDEX_OFFSET = BLOB_SIZE - INDEX_SIZE

SALT_LEN = 16
IV_LEN = 12
TAG_LEN = 16

def group_files_by_password(root_dir: str) -> dict:
    print(f"[*] Scanning directory: '{root_dir}' for '.passwd' rules...")
    passwd_file = os.path.join(root_dir, ".passwd")
    rules = {}

    # Parse the password rules
    if os.path.exists(passwd_file):
        with open(passwd_file, "r") as file_obj:
            for line in file_obj:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue

                path, password = line.split(None, 1)
                path = path.rstrip("/")

                if path == ".":
                    rules["."] = password
                else:
                    rules[os.path.normpath(path)] = password
    else:
        print("[!] No '.passwd' file found. All files will need a default rule.")

    # Helper to find the nearest applicable password rule
    def resolve_password(rel_path: str) -> str:
        path = os.path.normpath(rel_path)
        while True:
            if path in rules:
                return rules[path]
            if path == "." or path == "":
                return rules.get(".", None)
            # Walk up one directory level
            path = os.path.dirname(path)

    # Group the files
    groups = defaultdict(list)
    for root, _, files in os.walk(root_dir):
        for name in files:
            if name == ".passwd":
                continue

            full_path = os.path.join(root, name)
            rel_path = os.path.relpath(full_path, root_dir)
            rel_dir = os.path.dirname(rel_path) or "."

            password = resolve_password(rel_dir)
            if not password:
                print(f"[!] Warning: No password rule matched for '{rel_path}'. Skipping.")
                continue

            groups[password].append(rel_path)

    print(f"[*] Found {sum(len(v) for v in groups.values())} files across {len(groups)} password group(s).")
    return dict(groups)

def generate_random_blob_name() -> str:
    alphabet = string.ascii_letters + string.digits
    return ''.join(secrets.choice(alphabet) for _ in range(12))

def derive_encryption_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=200000,
    )
    return kdf.derive(password.encode())

def create_new_blob(blob_dir: str):
    blob_name = generate_random_blob_name()
    blob_path = os.path.join(blob_dir, blob_name)

    print(f"[*] Creating new blob: {blob_name}")
    blob_file = open(blob_path, "wb+")
    blob_file.truncate(BLOB_SIZE)  # Pre-allocate exactly 32MB

    return blob_file, blob_name

# MAIN PACKING LOGIC
def write_encrypted_blobs(root_dir: str, groups: dict, blob_dir: str = "blobs"):
    # Prepare clean output directory
    if os.path.isdir(blob_dir):
        print(f"[*] Clearing existing output directory: '{blob_dir}'")
        shutil.rmtree(blob_dir)
    os.makedirs(blob_dir, exist_ok=True)

    global_blob_list = []

    # Process each password group independently
    for password, files in groups.items():
        print(f"\n[+] Processing group with {len(files)} files...")

        group_salt = secrets.token_bytes(SALT_LEN)
        group_key = derive_encryption_key(password, group_salt)
        cipher = AESGCM(group_key)

        # Setup the first blob
        active_blob_file, active_blob_name = create_new_blob(blob_dir)
        global_blob_list.append(active_blob_name)

        write_cursor = 0   # Tracks current byte position in the active blob
        file_index = {}    # Maps filename -> { blob_name: [start_byte, end_byte] }

        # Process every file in the group
        for filename in files:
            print(f"    -> Encrypting: {filename}")
            full_path = os.path.join(root_dir, filename)

            with open(full_path, "rb") as target_file:
                raw_data = target_file.read()

            # Encrypt the file data
            file_iv = secrets.token_bytes(IV_LEN)
            ciphertext = cipher.encrypt(file_iv, raw_data, associated_data=None)

            # Payload Layout: [Salt 16b] [IV 12b] [Ciphertext...]
            encrypted_payload = group_salt + file_iv + ciphertext
            payload_offset = 0

            file_index[filename] = {}

            # Write payload to blobs (Chunking logic if it overflows 32MB)
            while payload_offset < len(encrypted_payload):

                remaining_blob_space = BLOB_SIZE - write_cursor
                remaining_payload_data = len(encrypted_payload) - payload_offset
                chunk_size = min(remaining_blob_space, remaining_payload_data)

                start_byte = write_cursor
                end_byte = write_cursor + chunk_size - 1

                # Write the chunk
                active_blob_file.seek(write_cursor)
                active_blob_file.write(encrypted_payload[payload_offset : payload_offset + chunk_size])

                # Record the location in the index map
                if active_blob_name not in file_index[filename]:
                    file_index[filename][active_blob_name] = [start_byte, end_byte]
                else:
                    file_index[filename][active_blob_name][1] = end_byte

                write_cursor += chunk_size
                payload_offset += chunk_size

                # If the blob is completely full, close it and start a new one
                if write_cursor == BLOB_SIZE:
                    active_blob_file.close()
                    active_blob_file, active_blob_name = create_new_blob(blob_dir)
                    global_blob_list.append(active_blob_name)
                    write_cursor = 0

        # Save the Encrypted Index for this group
        print(f"\n[*] Finalizing group. Encrypting index...")
        index_json_bytes = json.dumps(file_index).encode()

        index_iv = secrets.token_bytes(IV_LEN)
        index_ciphertext = cipher.encrypt(index_iv, index_json_bytes, associated_data=None)

        # Index Layout: [Salt 16b] [IV 12b] [Length 4b] [Ciphertext...]
        encrypted_index_payload = (
            group_salt +
            index_iv +
            len(index_ciphertext).to_bytes(4, byteorder="big") +
            index_ciphertext
        )

        # Ensure we have space in the current blob's reserved index region (last 16KB)
        if write_cursor <= INDEX_OFFSET and len(encrypted_index_payload) <= INDEX_SIZE:
            print(f"[*] Writing index to end of current blob: {active_blob_name}")
            target_blob_file = active_blob_file
        else:
            print(f"[*] Current blob full. Creating empty blob for index...")
            active_blob_file.close()
            target_blob_file, target_blob_name = create_new_blob(blob_dir)
            global_blob_list.append(target_blob_name)

        # Write to the exact INDEX_OFFSET
        target_blob_file.seek(INDEX_OFFSET)
        target_blob_file.write(encrypted_index_payload)
        target_blob_file.close()

    # Write the master manifest (List of all generated blobs)
    manifest_path = os.path.join(blob_dir, "blobs.json")
    print(f"\n[*] Writing global blob manifest: '{manifest_path}'")
    with open(manifest_path, "w") as manifest_file:
        json.dump(global_blob_list, manifest_file)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python packer.py <directory_to_pack>")
        sys.exit(1)

    input_dir = sys.argv[1]

    print("========================================")
    print("        WebFS Packer Started            ")
    print("========================================")

    password_groups = group_files_by_password(input_dir)
    write_encrypted_blobs(input_dir, password_groups)

    print("\n========================================")
    print("        Process Completed Successfully  ")
    print("========================================")
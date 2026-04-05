import os
import json
import sys
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

# CONSTANTS & CONFIGURATION
BLOB_DIR = "./blobs"
EXTRACT_DIR = "./unpacked"

BLOB_SIZE = 32 * 1024 * 1024
INDEX_REGION = 16 * 1024
INDEX_OFFSET = BLOB_SIZE - INDEX_REGION

def derive_encryption_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=200000)
    return kdf.derive(password.encode())

def try_decrypt_index(blob_path: str, password: str) -> dict:
    with open(blob_path, "rb") as blob_file:
        blob_file.seek(INDEX_OFFSET)
        region = blob_file.read(INDEX_REGION)

    if len(region) < 32:
        return None

    salt, iv = region[:16], region[16:28]
    ciphertext_length = int.from_bytes(region[28:32], byteorder="big")
    ciphertext = region[32 : 32 + ciphertext_length]

    try:
        key = derive_encryption_key(password, salt)
        cipher = AESGCM(key)
        plaintext = cipher.decrypt(iv, ciphertext, associated_data=None)
        return json.loads(plaintext.decode('utf-8'))
    except Exception:
        return None

def find_valid_index(password: str) -> dict:
    print("\n[*] Scanning blobs for a matching index...")
    if not os.path.exists(BLOB_DIR):
        print(f"[!] Directory '{BLOB_DIR}' not found.")
        return None

    for blob_filename in os.listdir(BLOB_DIR):
        if not os.path.isfile(os.path.join(BLOB_DIR, blob_filename)) or blob_filename.endswith(".json"):
            continue

        blob_path = os.path.join(BLOB_DIR, blob_filename)
        index_data = try_decrypt_index(blob_path, password)
        if index_data:
            print(f"[+] Success! Valid index unlocked in blob: {blob_filename}")
            return index_data
    return None

def read_blob_range(blob_name: str, start_byte: int, end_byte: int) -> bytes:
    path = os.path.join(BLOB_DIR, blob_name)
    with open(path, "rb") as blob_file:
        blob_file.seek(start_byte)
        return blob_file.read(end_byte - start_byte + 1)

def retrieve_encrypted_file_bytes(chunk_list: list) -> bytes:
    raw_payload = b""
    for blob_name, start_byte, end_byte in chunk_list:
        print(f"[*] Reading chunk from {blob_name} (Bytes {start_byte} to {end_byte})")
        raw_payload += read_blob_range(blob_name, start_byte, end_byte)
    return raw_payload

def decrypt_file_payload(payload: bytes, password: str) -> bytes:
    print("[*] Decrypting file payload...")
    salt, iv, ciphertext = payload[:16], payload[16:28], payload[28:]
    key = derive_encryption_key(password, salt)
    cipher = AESGCM(key)
    return cipher.decrypt(iv, ciphertext, associated_data=None)

def main():
    print("========================================")
    print("       WebFS Unpacker Utility           ")
    print("========================================")

    password = input("\nEnter vault password: ")

    index_data = find_valid_index(password)
    if not index_data:
        print("\n[!] Error: No valid index found. Incorrect password or corrupted blobs.")
        sys.exit(1)

    # Parse the new index structure
    available_files = list(index_data["files"].keys())

    print("\nFiles available in this vault:")
    print("-" * 40)
    for i, file_name in enumerate(available_files):
        size_kb = index_data["files"][file_name].get("size", 0) / 1024
        print(f"  [{i}] {file_name} ({size_kb:.1f} KB)")
    print("-" * 40)

    try:
        choice = int(input("\nEnter the number of the file to extract: "))
        target_file_path = available_files[choice]
    except (ValueError, IndexError):
        print("[!] Invalid selection. Exiting.")
        sys.exit(1)

    print(f"\n[*] Initiating extraction for: {target_file_path}")

    chunk_list = index_data["files"][target_file_path]["chunks"]
    encrypted_payload = retrieve_encrypted_file_bytes(chunk_list)
    plaintext_data = decrypt_file_payload(encrypted_payload, password)

    output_path = os.path.join(EXTRACT_DIR, target_file_path)
    os.makedirs(os.path.dirname(output_path), exist_ok=True)

    with open(output_path, "wb") as output_file:
        output_file.write(plaintext_data)

    print(f"\n[+] File successfully extracted to: {os.path.abspath(output_path)}")

if __name__ == "__main__":
    os.makedirs(EXTRACT_DIR, exist_ok=True)
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Process cancelled by user.")
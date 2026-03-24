# WebFS: Serverless Encrypted File Vault

WebFS is a secure, fully static web application that allows you to host, share, and preview encrypted files directly in the browser.

It requires **no backend server, no database, and no complex API**. The entire project is simply a collection of static files (HTML, CSS, JS, and encrypted binary blobs) that can be hosted on any basic web server, CDN, or static hosting provider (like GitHub Pages, Vercel, or AWS S3).

## Key Features

* **Zero-Knowledge Architecture:** Files are encrypted locally using AES-256-GCM. The hosting provider never sees your plaintext files or passwords.
* **Service Worker:** The frontend UI is completely oblivious to the encryption. It simply requests a file (e.g., `fetch('/document.pdf')`), and the background Service Worker transparently intercepts the request, fetches the required encrypted bytes, decrypts them on the fly, and serves them to the UI.
* **Isolated & Mergeable Vaults:** Files are grouped into separate encrypted "vaults" based on directory paths. You can unlock a single vault to view its contents, or unlock multiple vaults sequentially—the Service Worker seamlessly merges them into a unified virtual file system.
* **Rich Native Previews:** Includes built-in support for previewing Media (Images, Videos), Documents (PDF, DOCX), and Text (Markdown, Source Code) using lightweight external libraries.
* **Fully Static:** Once packed, the output is just a static website and a folder of binary blobs.

---

## Architecture & Flow

1. **Packer (`packer.py`):** A Python script scans your target directory, normalizes filenames, groups files by their password rules (defined in a `.passwd` file), and packs them tightly into fixed-size (32MB) encrypted blobs.
2. **Web UI (`index.html` & `main.js`):** A modern, dark-mode frontend that requests files and renders previews (using `marked`, `highlight.js`, `viewerjs`, `plyr`, and `mammoth`).
3. **Decryption Engine (`sw.js`):** A Service Worker that acts as a local proxy. It handles PBKDF2 key derivation, fetches specific byte ranges from the encrypted blobs, decrypts the payloads, and reconstructs the files in browser memory.
4. **Unpacker (`unpacker.py`):** An included CLI utility to locally test, verify, and extract files directly from the encrypted blobs without a browser.

---

## Getting Started

A preview of the app is hosted as a [Github Page](shashotonur.github.io/webfs) where a sample `files/` firectory is packed against seven passwords in the `files/.passwd` file.

### 1. Requirements
To pack your files, you need Python 3 and the `cryptography` package:
```bash
pip install cryptography
```

### 2. Define Your Vaults (`.passwd`)
In the root of the directory you want to encrypt (e.g., `./files`), create a `.passwd` file. This file dictates which directories belong to which encrypted vault. Rules cascade downwards unless overridden.

*Example `.passwd` file:*
```text
# Root password (fallback for anything not explicitly grouped)
. important_core_password

# dir1 (# is used to comment out lines)
./dir1/ knowledge_base_sigma54

# these lines will not be read by the packer script)
./dir1/subdir/ dev_guides11_lambda
```

### 3. Pack the Files
Run the packer script, pointing it to your target directory.
*Note: The packer expects normalized filenames, as it may cause problems with complex names.*

```bash
python scripts/packer.py ./path/to/target/directory
```
This will generate the encrypted blobs inside the `blobs/` directory, alongside a `blobs.json` manifest.
There is already a sample `files/` directory with a `files/.passwd` file which has been packed as an example in the blobs directory. They can be read via the Web UI using the passwords from the `files/.passwd` file.

### 4. Serve the Application
You can test it locally using Python's built-in HTTP server:
```bash
python scripts/server.py -p 5000
```
Navigate to `http://127.0.0.1:5000/webfs` in your browser. Enter one of the passwords defined in your `files/.passwd` file to decrypt that specific vault. Enter another password to merge a second vault into your current session.

---

## Built With

The WebFS frontend relies on a curated stack of lightweight, highly-performant libraries to render the decrypted byte arrays natively in the browser:

* **[Marked.js](https://marked.js.org/)** - High-speed Markdown parsing.
* **[Highlight.js](https://highlightjs.org/)** - Syntax highlighting for source code.
* **[Viewer.js](https://fengyuanchen.github.io/viewerjs/)** - JavaScript image gallery and zooming.
* **[Plyr](https://plyr.io/)** - Simple, accessible, and customizable media player.
* **[Mammoth.js](https://github.com/mwilliamson/mammoth.js/)** - Client-side `.docx` to HTML rendering.

---

## Security Notes

* **In-Memory Decryption:** Keys and decrypted files are kept strictly in browser memory. Killing the serviceworker by closing the tab or manually destroys the plaintext data.
* **Blob Range Requests:** WebFS does not load massive files into memory all at once. The Service Worker issues HTTP `Range` requests to fetch only the exact encrypted bytes needed from the 32MB blobs.
* **Lock All:** The UI includes a "Lock All Vaults" panic button which instantly flushes the active Service Worker state and memory arrays.

---

## LICENCE

This project is licenced under the [MIT LICENCE](LICENCE)
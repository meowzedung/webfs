const CONFIG = {
    BLOB_DIR: 'blobs/',
    BLOB_SIZE: 32 * 1024 * 1024,      // 32 MB
    INDEX_REGION: 16 * 1024,          // 16 KB
    get INDEX_OFFSET() {
        return this.BLOB_SIZE - this.INDEX_REGION;
    }
};

const IGNORED_PATHS = [
    'blobs/',
    'static/',
    'scripts/',
    'unpacked/',
    'index.html',
    'sw.js',
    'icons.js'
];

let unlockedVaults = [];
let pendingPassword = null;
let vaultCounter = 1;

async function deriveKey(password, salt) {
    const encoder = new TextEncoder();
    const baseKey = await crypto.subtle.importKey(
        "raw", encoder.encode(password), "PBKDF2", false, ["deriveKey"]
    );
    return crypto.subtle.deriveKey(
        { name: "PBKDF2", salt: salt, iterations: 200000, hash: "SHA-256" },
        baseKey, { name: "AES-GCM", length: 256 }, false, ["decrypt"]
    );
}

async function fetchByteRange(blobName, start, end) {
    const targetUrl = `${self.registration.scope}${CONFIG.BLOB_DIR}${blobName}`;
    const response = await fetch(targetUrl, {
        headers: { Range: `bytes=${start}-${end}` }
    });

    const buffer = await response.arrayBuffer();
    const data = new Uint8Array(buffer);

    if (response.status === 200 && data.length > (end - start + 1)) {
        console.warn(`[WebFS] Server ignored Range request for ${blobName}. Manually slicing buffer.`);
        return data.slice(start, end + 1);
    }

    return data;
}

async function readIndexFromBlob(blobName, password) {
    const region = await fetchByteRange(
        blobName, CONFIG.INDEX_OFFSET, CONFIG.INDEX_OFFSET + CONFIG.INDEX_REGION - 1
    );

    // If region is smaller than headers, it's not a valid index blob
    if (region.length < 32) return null;

    const salt = region.slice(0, 16);
    const iv = region.slice(16, 28);
    const length = new DataView(region.buffer, 28, 4).getUint32(0);
    const ciphertext = region.slice(32, 32 + length);

    try {
        const key = await deriveKey(password, salt);
        const plaintextBuffer = await crypto.subtle.decrypt(
            { name: 'AES-GCM', iv }, key, ciphertext
        );
        const decodedText = new TextDecoder().decode(plaintextBuffer);
        return JSON.parse(decodedText);
    } catch (error) {
        return null;
    }
}

async function decryptVaultIndex(blobList, password) {
    for (const blobName of blobList) {
        const indexData = await readIndexFromBlob(blobName, password);
        if (indexData) return indexData;
    }
    return null;
}

async function reconstructFilePayload(fileEntry) {
    // Iterate over the ordered chunks array: [[blobName, start, end], ...]
    const chunkPromises = fileEntry.chunks.map(([blobName, start, end]) =>
        fetchByteRange(blobName, start, end)
    );

    // Promise.all preserves the exact array order, ensuring perfect reconstruction
    const chunks = await Promise.all(chunkPromises);
    const totalSize = chunks.reduce((sum, chunk) => sum + chunk.length, 0);
    const payload = new Uint8Array(totalSize);

    let offset = 0;
    for (const chunk of chunks) {
        payload.set(chunk, offset);
        offset += chunk.length;
    }
    return payload;
}

async function decryptFilePayload(payload, password) {
    const salt = payload.slice(0, 16);
    const iv = payload.slice(16, 28);
    const ciphertext = payload.slice(28);

    const key = await deriveKey(password, salt);
    const plaintextBuffer = await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv }, key, ciphertext
    );

    return new Uint8Array(plaintextBuffer);
}

async function handleVirtualRequest(relativeUrl) {

    // --- Endpoint: Vault Unlock & Index Merging ---
    if (relativeUrl === "get-index") {

        if (pendingPassword) {
            const blobListResponse = await fetch(`${self.registration.scope}blobs/blobs.json`);
            const blobList = await blobListResponse.json();

            const indexData = await decryptVaultIndex(blobList, pendingPassword);

            if (indexData) {
                const exists = unlockedVaults.some(v => v.password === pendingPassword);
                if (!exists) {
                    unlockedVaults.push({
                        id: `vault_${Date.now()}_${Math.random().toString(36).substr(2, 5)}`,
                        name: `Vault ${vaultCounter++}`, password: pendingPassword, indexData
                    });
                }
            } else {
                pendingPassword = null;
                return createJsonResponse({ error: "Invalid password or vault not found" }, 401);
            }
            pendingPassword = null;
        }

        if (unlockedVaults.length === 0) {
            return createJsonResponse({ error: "Vaults locked" }, 401);
        }

        const mergedKeys = new Set();
        const activeVaultsData = [];

        for (const vault of unlockedVaults) {
            const filesInVault = Object.keys(vault.indexData.files || {});
            filesInVault.forEach(k => mergedKeys.add(k));
            activeVaultsData.push({ id: vault.id, name: vault.name, count: filesInVault.length });
        }

        return createJsonResponse({ files: Array.from(mergedKeys), vaults: activeVaultsData }, 200);
    }

    // --- Endpoint: Virtual File Access ---
    const fileName = decodeURIComponent(relativeUrl);

    let targetVault = null;
    for (const vault of unlockedVaults) {
        if (vault.indexData && vault.indexData.files && vault.indexData.files[fileName]) {
            targetVault = vault;
            break;
        }
    }

    if (targetVault) {
        // Retrieve the fileEntry from indexData.files
        const fileEntry = targetVault.indexData.files[fileName];

        try {
            const encryptedPayload = await reconstructFilePayload(fileEntry);
            const decryptedFile = await decryptFilePayload(encryptedPayload, targetVault.password);

            // Support streaming video??
            return new Response(decryptedFile);
        } catch (error) {
            console.error(`[WebFS] Failed to decrypt file: ${fileName}`, error);
            return new Response("Decryption failed or file corrupted", { status: 500 });
        }
    }

    return new Response("Not Found", { status: 404 });
}

function createJsonResponse(data, status) {
    return new Response(JSON.stringify(data), {
        status: status, headers: { 'Content-Type': 'application/json' }
    });
}

self.addEventListener('install', event => event.waitUntil(self.skipWaiting()));
self.addEventListener('activate', event => event.waitUntil(self.clients.claim()));

self.addEventListener('message', event => {
    if (event.data?.type === "add-password") {
        pendingPassword = event.data.password;
    } else if (event.data?.type === "lock-vault") {
        unlockedVaults = unlockedVaults.filter(v => v.id !== event.data.id);
        if (unlockedVaults.length === 0) vaultCounter = 1;
    } else if (event.data?.type === "lock-all-vaults") {
        unlockedVaults = []; pendingPassword = null; vaultCounter = 1;
    }
});

self.addEventListener('fetch', event => {
    const scope = self.registration.scope;

    // Ignore requests that don't belong to the app
    if (!event.request.url.startsWith(scope)) return;

    const relativeUrl = event.request.url.slice(scope.length);

    // Bypass empty route (index page load)
    if (relativeUrl === "") return;

    if (relativeUrl === "keepalive") {
        event.respondWith(new Response(null, { status: 204 }));
        return;
    }

    // Do NOTHING for static assets
    if (IGNORED_PATHS.some(prefix => relativeUrl.startsWith(prefix))) return;

    event.respondWith(handleVirtualRequest(relativeUrl));
});
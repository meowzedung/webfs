if (!window.location.pathname.endsWith('/') && !window.location.pathname.endsWith('.html')) {
    window.location.replace(window.location.href + '/');
}

let fileIndex = []

const vaultModal = document.getElementById("vaultModal");
const manageVaultsBtn = document.getElementById("manageVaultsBtn");
const closeModalBtn = document.getElementById("closeModalBtn");
const lockAllBtn = document.getElementById("lockAllBtn");

let basePath = window.location.pathname;
if (basePath.endsWith('.html')) {
    basePath = basePath.substring(0, basePath.lastIndexOf('/'));
}
if (!basePath.endsWith('/')) {
    basePath += '/';
}
const baseURL = window.location.origin + basePath;

window.addEventListener('DOMContentLoaded', async () => {
    if (!('serviceWorker' in navigator)) {
        document.body.innerHTML = '<h2 style="color:white; text-align:center; margin-top:50px;">Service Workers are required for WebFS.</h2>';
        return;
    }

    try {

        await navigator.serviceWorker.register(baseURL + "sw.js");
        await navigator.serviceWorker.ready;

        if (!navigator.serviceWorker.controller) {
            console.warn("Service Worker bypassed (Hard Refresh detected). Restoring control...");
            window.location.reload();
            return; // Halt execution until the reload finishes
        }

        setInterval(() => {
            fetch(baseURL + 'keepalive', { cache: "no-store" });
        }, 20_000);
        const res = await fetch(baseURL + 'get-index');

        if (res.ok) {
            const payload = await res.json();
            fileIndex = payload.files;
            renderTree(buildTree(fileIndex));
            renderActiveVaults(payload.vaults);
            updateUIUnlocked();
        } else {
            updateUILocked();
        }
    } catch(e) {
        console.error("Boot Sequence Error:", e);
        updateUILocked();
    }
});

// Core Events
document.getElementById("unlockBtn").addEventListener("click", unlock);
document.getElementById("password").addEventListener("keypress", (e) => {
    if(e.key === "Enter") unlock();
});

// Modal Toggles
manageVaultsBtn.addEventListener("click", () => vaultModal.classList.add("active"));
closeModalBtn.addEventListener("click", () => vaultModal.classList.remove("active"));

document.getElementById("togglePasswordBtn").addEventListener("click", function() {
    const passwordInput = document.getElementById("password");
    if (passwordInput.type === "password") {
        passwordInput.type = "text";
        this.innerHTML = Icons.eyeOffPath;
    } else {
        passwordInput.type = "password";
        this.innerHTML = Icons.eyePath;
    }
});

function setLoader(show, text = 'Processing...') {
    const loader = document.getElementById('globalLoader');
    const loaderText = document.getElementById('loaderText');
    if (show) {
        loaderText.textContent = text;
        loader.classList.add('visible');
    } else {
        loader.classList.remove('visible');
    }
}

const sleep = (ms) => new Promise(resolve => setTimeout(resolve, ms));

document.getElementById("searchInput").addEventListener("input", (e) => {
    const query = e.target.value.toLowerCase();
    if (!query) {
        renderTree(buildTree(fileIndex));
        return;
    }
    const filteredPaths = fileIndex.filter(path => {
        const filename = path.split('/').pop().toLowerCase();
        return filename.includes(query);
    });
    renderTree(buildTree(filteredPaths), document.getElementById("fileTree"), "", true);
});

async function unlock(){
    const password = document.getElementById("password").value;
    if (!password) return;

    setLoader(true, 'Looking for vault...');
    try {
        const reg = await navigator.serviceWorker.ready
        const sw = navigator.serviceWorker.controller || reg.active

        sw.postMessage({ type: "add-password", password })
        await sleep(50);

        const res = await fetch(baseURL + 'get-index')

        if(!res.ok){
            setLoader(true, 'Unlock failed. Check your password.');
            await sleep(2500);
            return;
        }

        const payload = await res.json()
        fileIndex = payload.files;

        renderTree(buildTree(fileIndex))
        renderActiveVaults(payload.vaults);

        updateUIUnlocked();

    } finally {
        setLoader(false);
    }
}

window.lockVault = async function(vaultId) {
    setLoader(true, 'Locking vault...');
    try {
        const reg = await navigator.serviceWorker.ready
        const sw = navigator.serviceWorker.controller || reg.active

        sw.postMessage({ type: "lock-vault", id: vaultId });
        await sleep(50);

        const res = await fetch(baseURL + 'get-index');

        if (!res.ok) {
            updateUILocked();
        } else {
            const payload = await res.json();
            fileIndex = payload.files;
            renderTree(buildTree(fileIndex));
            renderActiveVaults(payload.vaults);
        }
    } finally {
        setLoader(false);
    }
}

window.lockAllVaults = async function() {
    setLoader(true, 'Locking all vaults...');
    try {
        const reg = await navigator.serviceWorker.ready;
        const sw = navigator.serviceWorker.controller || reg.active;

        sw.postMessage({ type: "lock-all-vaults" });
        await sleep(50);

        updateUILocked();
    } finally {
        setLoader(false);
    }
}

lockAllBtn.addEventListener("click", lockAllVaults);

function renderActiveVaults(vaults) {
    const container = document.getElementById("activeVaultsContainer");
    container.innerHTML = vaults.map(v => `
        <div class="vault-tag">
            <div class="vault-tag-info">
                ${Icons.checkGreen}
                <span>${escapeHTML(v.name)}</span>
                <span class="count">${v.count} files</span>
            </div>
            <button class="btn-lock-vault" onclick="lockVault('${v.id}')" title="Lock this vault">
                ${Icons.lockSmall}
            </button>
        </div>
    `).join('');
}

function updateUIUnlocked() {
    document.getElementById("password").value = "";
    document.getElementById("unlockBtn").innerText = "Add Another Vault";

    vaultModal.classList.remove("active");
    manageVaultsBtn.style.display = "flex";
    closeModalBtn.style.display = "block";

    document.getElementById("activeVaultsContainer").style.display = "flex";
    document.getElementById("searchContainer").style.display = "block";
    lockAllBtn.style.display = "flex";

    document.getElementById("vaultStatus").innerText = "Vault(s) Unlocked";
    document.getElementById("vaultInstruction").innerText = "Click on a directory to expand or a file to preview.";
}

function updateUILocked() {
    fileIndex = [];
    document.getElementById("fileTree").innerHTML = "";
    document.getElementById("searchInput").value = "";
    document.getElementById("password").value = "";
    document.getElementById("unlockBtn").innerText = "Unlock Vault";

    vaultModal.classList.add("active");
    manageVaultsBtn.style.display = "none";
    closeModalBtn.style.display = "none";

    document.getElementById("activeVaultsContainer").style.display = "none";
    document.getElementById("searchContainer").style.display = "none";
    lockAllBtn.style.display = "none";

    document.getElementById("previewContent").innerHTML = `
        <div class="empty-state">
            ${Icons.lockedBig}
            <h2 id="vaultStatus">Vault Locked</h2>
            <p id="vaultInstruction">Access the Vault Manager to decrypt and access your files.</p>
        </div>
    `;
}

function renderTree(tree, parent = document.getElementById("fileTree"), base = "", forceExpand = false){
    parent.innerHTML = ""

    for(const name in tree){
        const node = tree[name]
        const path = base ? base + "/" + name : name
        const div = document.createElement("div")

        if(Object.keys(node).length === 0){
            div.className = "tree-item file"
            div.innerHTML = `
                ${Icons.file}
                <span class="label">${escapeHTML(name)}</span>
            `
            div.onclick = (e) => {
                e.stopPropagation();
                document.querySelectorAll('.tree-item').forEach(el => el.classList.remove('active'));
                div.classList.add('active');
                openFile(path);
            }
        } else {
            div.className = "folder-container"

            const folderHeader = document.createElement("div")
            folderHeader.className = `tree-item folder ${forceExpand ? 'open' : ''}`
            folderHeader.innerHTML = `
                ${Icons.folder}
                <span class="label">${escapeHTML(name)}</span>
            `

            const children = document.createElement("div")
            children.className = `folder-children ${forceExpand ? '' : 'collapsed'}`
            renderTree(node, children, path, forceExpand)

            folderHeader.onclick = (e) => {
                e.stopPropagation();
                folderHeader.classList.toggle('open');
                children.classList.toggle('collapsed');
            }

            div.appendChild(folderHeader)
            div.appendChild(children)
        }
        parent.appendChild(div)
    }
}

function buildTree(paths){
    const root = {}
    for(const path of paths){
        const parts = path.split("/")
        let node = root
        for(const part of parts){
            if(!node[part]) node[part] = {}
            node = node[part]
        }
    }
    return root
}

const imageExt = ['jpg', 'jpeg', 'png', 'gif', 'webp', 'svg', 'avif', 'bmp', 'ico', 'tiff'];
const videoExt = ['mp4', 'webm', 'ogg', 'mov', 'avi', 'mkv', 'flv', 'wmv', 'm4v'];
const mdExt = ['md','markdown'];
const pdfExt = ['pdf'];
const docxExt = ['doc', 'docx'];

async function openFile(path){
    const preview = document.getElementById("previewContent")
    const extension = path.split('.').pop().toLowerCase()
    const filename = path.split('/').pop()

    setLoader(true, `Decrypting & loading ${filename}...`);
    try {
        const res = await fetch(baseURL + path)
        const resClone = res.clone()

        if(imageExt.includes(extension)){
            const blob = await res.blob()
            const url = URL.createObjectURL(blob)
            preview.innerHTML = `<div class="media-container"><img id="previewImage" src="${url}"></div>`
            new Viewer(document.getElementById('previewImage'))
            return
        }

        if(videoExt.includes(extension)){
            const blob = await res.blob()
            const url = URL.createObjectURL(blob)
            preview.innerHTML = `
                <div class="preview-header">
                    <span class="file-name">${escapeHTML(filename)}</span>
                    <a class="btn-secondary" href="${url}" download="${escapeHTML(filename)}">
                        ${Icons.download}
                        Download Video
                    </a>
                </div>
                <div class="video-wrapper">
                    <video id="player" playsinline controls><source src="${url}"></video>
                </div>
            `
            new Plyr('#player')
            return
        }

        if(pdfExt.includes(extension)){
            const rawBlob = await res.blob();
            const pdfBlob = new Blob([rawBlob], { type: 'application/pdf' });
            const url = URL.createObjectURL(pdfBlob);
            preview.innerHTML = `
                <div class="preview-header">
                    <span class="file-name">${escapeHTML(filename)}</span>
                    <a class="btn-secondary" href="${url}" download="${escapeHTML(filename)}">
                        ${Icons.download}
                        Download PDF
                    </a>
                </div>
                <div class="pdf-wrapper">
                    <iframe src="${url}#view=FitH" title="${escapeHTML(filename)}"></iframe>
                </div>
            `;
            return;
        }

        if(docxExt.includes(extension)){
            const arrayBuffer = await res.arrayBuffer();
            try {
                const result = await mammoth.convertToHtml({ arrayBuffer: arrayBuffer });
                const url = URL.createObjectURL(new Blob([arrayBuffer]));
                preview.innerHTML = `
                    <div class="preview-header">
                        <span class="file-name">${escapeHTML(filename)}</span>
                        <a class="btn-secondary" href="${url}" download="${escapeHTML(filename)}">
                            ${Icons.download}
                            Download DOCX
                        </a>
                    </div>
                    <div class="markdown-body docx-body">${result.value}</div>
                `;
            } catch (err) {
                console.error(err);
                preview.innerHTML = `<div class="fallback"><h3>Failed to preview DOCX</h3></div>`;
            }
            return;
        }

        if(await checkIsUTF8(resClone)){
            const text = await res.text()
            const headerHtml = `
                <div class="preview-header">
                    <span class="file-name">${escapeHTML(filename)}</span>
                    <button id="copyBtn" class="btn-secondary" onclick="copyText()">
                        ${Icons.copy}
                        Copy to Clipboard
                    </button>
                </div>
            `;

            if(mdExt.includes(extension)){
                const html = marked.parse(text)
                preview.innerHTML = headerHtml + `<div class="markdown-body">${html}</div>`
                window._lastText = text

                const markdownContainer = preview.querySelector('.markdown-body');
                const images = markdownContainer.querySelectorAll('img');
                if (images.length > 0) new Viewer(markdownContainer);
                const videos = markdownContainer.querySelectorAll('video');
                videos.forEach(vid => { new Plyr(vid); });
                return
            }

            const highlighted = hljs.highlightAuto(text).value
            preview.innerHTML = headerHtml + `<div class="code-wrapper"><pre><code class="hljs">${highlighted}</code></pre></div>`
            window._lastText = text
            return
        }

        const blob = await res.blob()
        const url = URL.createObjectURL(blob)
        preview.innerHTML = `
            <div class="fallback">
                ${Icons.fallbackBig}
                <h3>No preview available for .${extension} files</h3>
                <a class="btn-secondary" href="${url}" download>Download Secure File</a>
            </div>
        `
    } finally {
        setLoader(false);
    }
}

function copyText(){
    if(window._lastText){
        navigator.clipboard.writeText(window._lastText).then(() => {
            const btn = document.getElementById('copyBtn');
            if(btn) {
                const original = btn.innerHTML;
                btn.innerHTML = `${Icons.copied} Copied!`;
                setTimeout(() => btn.innerHTML = original, 2000);
            }
        });
    }
}

async function checkIsUTF8(response) {
    try {
        const buffer = await response.arrayBuffer();
        const decoder = new TextDecoder('utf-8', { fatal: true });
        decoder.decode(buffer);
        return true;
    } catch (e) { return false; }
}

function escapeHTML(str){
    return str.replace(/[&<>'"]/g, tag => ({ '&':'&amp;', '<':'&lt;', '>':'&gt;', "'":'&#39;', '"':'&quot;' }[tag]));
}
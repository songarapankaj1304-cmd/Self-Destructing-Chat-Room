const socket = io();

// State
let currentRoomId = null;
let encryptionKey = null; // CryptoKey object
let isHost = false;

// DOM Elements
const loginScreen = document.getElementById('login-screen');
const chatScreen = document.getElementById('chat-screen');
const createBtn = document.getElementById('create-btn');
const joinBtn = document.getElementById('join-btn');
const roomIdInput = document.getElementById('room-id-input');
const roomKeyInput = document.getElementById('room-key-input');
const displayRoomId = document.getElementById('display-room-id');
const messagesContainer = document.getElementById('messages-container');
const messageInput = document.getElementById('message-input');
const sendBtn = document.getElementById('send-btn');
const endSessionBtn = document.getElementById('end-session-btn');
const copyInfoBtn = document.getElementById('copy-info-btn');

// New Password Inputs
const createRoomPasswordInput = document.getElementById('create-room-password');
const joinRoomPasswordInput = document.getElementById('join-room-password');

// --- Crypto Functions ---

async function generateKey() {
    return await window.crypto.subtle.generateKey(
        {
            name: "AES-GCM",
            length: 256
        },
        true,
        ["encrypt", "decrypt"]
    );
}

async function exportKey(key) {
    const exported = await window.crypto.subtle.exportKey("raw", key);
    return btoa(String.fromCharCode(...new Uint8Array(exported)));
}

async function importKey(base64Key) {
    try {
        const rawKey = Uint8Array.from(atob(base64Key), c => c.charCodeAt(0));
        return await window.crypto.subtle.importKey(
            "raw",
            rawKey,
            { name: "AES-GCM" },
            true,
            ["encrypt", "decrypt"]
        );
    } catch (e) {
        alert("Invalid Key format!");
        return null;
    }
}

async function encryptMessage(text, key) {
    const encoder = new TextEncoder();
    const data = encoder.encode(text);
    const iv = window.crypto.getRandomValues(new Uint8Array(12));
    const encrypted = await window.crypto.subtle.encrypt(
        {
            name: "AES-GCM",
            iv: iv
        },
        key,
        data
    );
    
    return {
        iv: btoa(String.fromCharCode(...iv)),
        ciphertext: btoa(String.fromCharCode(...new Uint8Array(encrypted)))
    };
}

async function decryptMessage(ivBase64, ciphertextBase64, key) {
    try {
        const iv = Uint8Array.from(atob(ivBase64), c => c.charCodeAt(0));
        const ciphertext = Uint8Array.from(atob(ciphertextBase64), c => c.charCodeAt(0));
        
        const decrypted = await window.crypto.subtle.decrypt(
            {
                name: "AES-GCM",
                iv: iv
            },
            key,
            ciphertext
        );
        
        const decoder = new TextDecoder();
        return decoder.decode(decrypted);
    } catch (e) {
        console.error("Decryption failed", e);
        return "[Encrypted Message - Failed to Decrypt]";
    }
}

// --- UI Logic ---

createBtn.addEventListener('click', async () => {
    const password = createRoomPasswordInput.value.trim();
    socket.emit('create_room', { password: password || null });
});

joinBtn.addEventListener('click', async () => {
    const roomId = roomIdInput.value.trim();
    const keyStr = roomKeyInput.value.trim();
    const password = joinRoomPasswordInput.value.trim();
    
    if (!roomId || !keyStr) {
        alert("Please enter both Room ID and Encryption Key");
        return;
    }
    
    encryptionKey = await importKey(keyStr);
    if (encryptionKey) {
        socket.emit('join_room', { roomId, password: password || null });
    }
});

sendBtn.addEventListener('click', sendMessage);
messageInput.addEventListener('keypress', (e) => {
    if (e.key === 'Enter') sendMessage();
});

async function sendMessage() {
    const text = messageInput.value.trim();
    if (!text || !currentRoomId || !encryptionKey) return;
    
    const { iv, ciphertext } = await encryptMessage(text, encryptionKey);
    const nonce = crypto.randomUUID ? crypto.randomUUID() : Math.random().toString(36).substring(2) + Date.now().toString(36);

    socket.emit('chat_message', {
        roomId: currentRoomId,
        message: ciphertext,
        iv: iv,
        nonce: nonce
    });
    
    messageInput.value = '';
}

endSessionBtn.addEventListener('click', () => {
    if (confirm("Are you sure? This will destroy the room for everyone.")) {
        socket.emit('end_session', currentRoomId);
    }
});

copyInfoBtn.addEventListener('click', async () => {
    if (!encryptionKey) return;
    const keyStr = await exportKey(encryptionKey);
    // Determine password from inputs (simplistic but works for session)
    const password = isHost ? createRoomPasswordInput.value.trim() : joinRoomPasswordInput.value.trim();
    
    let info = `Room ID: ${currentRoomId}\nEncryption Key: ${keyStr}`;
    if (password) {
        info += `\nRoom Password: ${password}`;
    }
    
    navigator.clipboard.writeText(info).then(() => {
        alert("Room info copied! Share securely.");
    });
});

// --- Socket Events ---

socket.on('room_created', async (roomId) => {
    currentRoomId = roomId;
    isHost = true;
    encryptionKey = await generateKey();
    
    showChatScreen();
    addSystemMessage(`Room created. Share the invite info securely.`);
    
    const keyStr = await exportKey(encryptionKey);
    // Prompt with info immediately for convenience
    // prompt("Copy this secure key:", keyStr);
});

socket.on('joined_room', (roomId) => {
    currentRoomId = roomId;
    isHost = false;
    showChatScreen();
    addSystemMessage("You joined the secure channel.");
});

socket.on('chat_message', async (data) => {
    const { senderId, message, iv } = data;
    const decryptedText = await decryptMessage(iv, message, encryptionKey);
    
    const isSelf = senderId === socket.id;
    addMessage(decryptedText, isSelf);
});

socket.on('system_message', (msg) => {
    addSystemMessage(msg);
});

socket.on('room_destroyed', (reason) => {
    alert(`Session ended: ${reason || 'Room destroyed'}.`);
    location.reload();
});

socket.on('error', (msg) => {
    alert(`Error: ${msg}`);
});

// --- Helper Functions ---

function showChatScreen() {
    loginScreen.classList.add('hidden');
    chatScreen.classList.remove('hidden');
    displayRoomId.textContent = currentRoomId;
    if (isHost) {
        endSessionBtn.classList.remove('hidden');
    }
}

function addMessage(text, isSelf) {
    const div = document.createElement('div');
    div.classList.add('message');
    div.classList.add(isSelf ? 'self' : 'other');
    // Security: Use textContent to prevent XSS from decrypted messages
    div.textContent = text;
    
    // Self-destruct timer bar
    const timerBar = document.createElement('div');
    timerBar.classList.add('timer-bar');
    div.appendChild(timerBar);
    
    messagesContainer.appendChild(div);
    messagesContainer.scrollTop = messagesContainer.scrollHeight;
    
    // Remove after 10 seconds
    setTimeout(() => {
        div.style.opacity = '0';
        setTimeout(() => {
            if (div.parentNode) {
                div.parentNode.removeChild(div);
            }
        }, 500); // Wait for fade out
    }, 10000);
}

function addSystemMessage(text) {
    const div = document.createElement('div');
    div.classList.add('message', 'system');
    div.textContent = text; // Secure text insertion
    messagesContainer.appendChild(div);
    messagesContainer.scrollTop = messagesContainer.scrollHeight;
}

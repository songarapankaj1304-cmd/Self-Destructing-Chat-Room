const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const { v4: uuidv4 } = require('uuid');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const xss = require('xss');
const path = require('path');
const crypto = require('crypto');
//1const argon2 = require('argon2');
function hashPassword(password) {
    return crypto
        .createHash('sha256')
        .update(password + "STATIC_SALT_123")
        .digest('hex');
}
//1
const app = express();
const server = http.createServer(app);
const io = new Server(server, {
    maxHttpBufferSize: 1e4, // 10KB max payload to prevent memory flooding
    pingTimeout: 5000,
    pingInterval: 10000
});

// --- CONSTANTS & LIMITS ---
const MAX_ROOMS = 50; // Global limit (Prevention #1)
const MAX_USERS_PER_ROOM = 5; // (Prevention #8)
const MAX_ROOM_LIFETIME = 60 * 60 * 1000; // 1 Hour
const MESSAGE_MAX_LENGTH = 5000; // 5000 chars (Prevention #3)
const HOST_GRACE_PERIOD = 10000; // 10 seconds for host to reconnect (Prevention #4)

// --- STATE MANAGEMENT ---
const rooms = {}; // { [roomId]: { hostId, users: Set, passwordHash, created, destroyTimer } }
const ipStats = {}; // { [ip]: { connections, createAttempts, joinAttempts, blockedUntil } }
const seenNonces = new Set(); // Replay protection (Prevention #13)

// Cleanup Nonces periodically
setInterval(() => {
    seenNonces.clear();
}, 60 * 1000); // Clear every minute (Simple sliding window alternative)

// Cleanup Stale Rooms
setInterval(() => {
    const now = Date.now();
    for (const roomId in rooms) {
        if (now - rooms[roomId].created > MAX_ROOM_LIFETIME) {
            destroyRoom(roomId, 'Session time limit reached');
        }
    }
}, 60 * 1000);

// Cleanup IP Stats
setInterval(() => {
    for (const ip in ipStats) {
        // Reset counters periodically
        ipStats[ip].createAttempts = 0;
        ipStats[ip].joinAttempts = 0;
        // Keep connections count accurate via socket events
        if (ipStats[ip].connections === 0) delete ipStats[ip];
    }
}, 60 * 1000);

// --- HELPER FUNCTIONS ---

function getIp(socket) {
    return socket.handshake.address;
}

function destroyRoom(roomId, reason) {
    if (rooms[roomId]) {
        // Clear any pending timers
        if (rooms[roomId].destroyTimer) clearTimeout(rooms[roomId].destroyTimer);
        
        io.to(roomId).emit('room_destroyed', reason);
        io.in(roomId).socketsLeave(roomId);
        delete rooms[roomId];
        console.log(`[DESTROY] Room ${roomId}: ${reason}`);
    }
}

// --- EXPRESS MIDDLEWARE ---

app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            scriptSrc: ["'self'", "'unsafe-inline'", "https://cdn.socket.io"],
            styleSrc: ["'self'", "'unsafe-inline'"],
        },
    },
}));

// HTTP Rate Limit
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 100,
    message: 'Too many HTTP requests.'
});
app.use(limiter);

app.use(express.static(path.join(__dirname, 'public')));
app.use(express.json());

// --- SOCKET.IO LOGIC ---

io.use((socket, next) => {
    const ip = getIp(socket);
    
    // Initialize IP Stats
    if (!ipStats[ip]) ipStats[ip] = { connections: 0, createAttempts: 0, joinAttempts: 0, blockedUntil: 0 };
    
    // DoS Protection: Connection Limit (Prevention #11)
    if (ipStats[ip].connections >= 10) {
        return next(new Error('Too many open connections'));
    }
    
    ipStats[ip].connections++;
    next();
});

io.on('connection', (socket) => {
    const ip = getIp(socket);
    console.log(`[CONNECT] ${socket.id} from ${ip}`);

    // Rate limiter for messages
    const socketRateLimit = { count: 0, lastReset: Date.now() };

    //4socket.on('create_room', async (data) => {
    socket.on('create_room', (data) => {
    //4
        // Rate Limit: Room Creation (Prevention #1)
        if (ipStats[ip].createAttempts >= 3) {
            return socket.emit('error', 'Rate limit exceeded: Too many room creations.');
        }
        ipStats[ip].createAttempts++;

        // Global Limit Check
        if (Object.keys(rooms).length >= MAX_ROOMS) {
            return socket.emit('error', 'Server at capacity. Try again later.');
        }

        const roomId = uuidv4();
        const password = data?.password; // Optional password

        // Validation
        if (password && (typeof password !== 'string' || password.length > 50)) {
             return socket.emit('error', 'Invalid password format');
        }

        let passwordHash = null;
        if (password) {
            //6try {
            //6    // Use 2id for hashing
            //6    //2passwordHash = await argon2.hash(password, { type: argon2.argon2id });
            //6    passwordHash = hashPassword(password);
            //6    //2
            //6} catch (err) {
            //6    console.error('Hashing error:', err);
            //6    return socket.emit('error', 'Internal server error during room creation.');
            //6}
            passwordHash = hashPassword(password);
            //6
        }

        rooms[roomId] = {
            hostId: socket.id,
            users: new Set([socket.id]),
            passwordHash: passwordHash,
            created: Date.now(),
            destroyTimer: null
        };

        socket.join(roomId);
        socket.emit('room_created', roomId);
        console.log(`[CREATE] Room ${roomId} by ${socket.id}`);
    });

    //5socket.on('join_room', async (data) => {
    socket.on('join_room', (data) => {
    //5
        const { roomId, password } = data || {};

        // Validation (Prevention #2)
        if (!roomId || typeof roomId !== 'string') return socket.emit('error', 'Invalid Room ID');
        
        // Rate Limit: Join Attempts (Brute-force protection)
        if (ipStats[ip].joinAttempts >= 20) {
             return socket.emit('error', 'Too many failed join attempts. Please wait.');
        }

        const room = rooms[roomId];

        if (!room) {
            ipStats[ip].joinAttempts++;
            return socket.emit('error', 'Room not found');
        }

        // Auth Check (Prevention #6)
        if (room.passwordHash) {
            if (!password) {
                ipStats[ip].joinAttempts++;
                return socket.emit('error', 'Room requires a password');
            }
            try {
                const isValid = await argon2.verify(room.passwordHash, password);
                //3if (!isValid) {
                //3    ipStats[ip].joinAttempts++;
                //3    return socket.emit('error', 'Incorrect Room Password');
                //3}
                const isValid = hashPassword(password) === room.passwordHash;
                if (!isValid) {
                    ipStats[ip].joinAttempts++;
                    return socket.emit('error', 'Incorrect Room Password');
                }
                //3
            } catch (err) {
                console.error('Verification error:', err);
                return socket.emit('error', 'Internal server error during verification.');
            }
        }

        // Max Users Check (Prevention #8)
        if (room.users.size >= MAX_USERS_PER_ROOM) {
            return socket.emit('error', 'Room is full');
        }

        room.users.add(socket.id);
        socket.join(roomId);
        socket.emit('joined_room', roomId);
        io.to(roomId).emit('system_message', 'A user has joined the chat.'); // (Prevention #14: Users can't fake this if UI handles correctly)
        console.log(`[JOIN] ${socket.id} joined ${roomId}`);
    });

    socket.on('chat_message', (data) => {
        // Schema Validation (Prevention #9)
        if (!data || typeof data !== 'object') return;
        const { roomId, message, iv, nonce } = data;

        if (typeof roomId !== 'string' || typeof message !== 'string' || typeof iv !== 'string' || typeof nonce !== 'string') {
            return socket.emit('error', 'Invalid payload format');
        }

        // Message Size Limit (Prevention #3)
        if (message.length > MESSAGE_MAX_LENGTH) {
            return socket.emit('error', 'Message too long');
        }

        // Replay Protection (Prevention #13)
        if (seenNonces.has(nonce)) {
            return console.warn(`[REPLAY DETECTED] Nonce ${nonce} from ${socket.id}`);
        }
        seenNonces.add(nonce);

        // Rate Limit per Socket (Prevention #7)
        const now = Date.now();
        if (now - socketRateLimit.lastReset > 1000) {
            socketRateLimit.count = 0;
            socketRateLimit.lastReset = now;
        }
        if (socketRateLimit.count > 5) {
            return socket.emit('error', 'You are sending messages too fast.');
        }
        socketRateLimit.count++;

        const room = rooms[roomId];
        if (room && room.users.has(socket.id)) {
            // Encryption "Sanity Check" (Prevention #10) - minimal check
            // We expect base64, so regex check could happen here, but simple length check is okay for now.
            
            io.to(roomId).emit('chat_message', {
                senderId: socket.id,
                message: xss(message),
                iv: xss(iv),
                timestamp: Date.now()
            });
        }
    });

    socket.on('end_session', (roomId) => {
        const room = rooms[roomId];
        if (room && room.hostId === socket.id) {
            destroyRoom(roomId, 'Host ended the session');
        }
    });

    socket.on('disconnect', () => {
        if (ipStats[ip]) ipStats[ip].connections = Math.max(0, ipStats[ip].connections - 1);
        console.log(`[DISCONNECT] ${socket.id}`);

        for (const roomId in rooms) {
            const room = rooms[roomId];
            if (room.users.has(socket.id)) {
                room.users.delete(socket.id);
                io.to(roomId).emit('system_message', 'A user has left the chat.');

                // Host Disconnect Logic (Prevention #4)
                if (socket.id === room.hostId) {
                    // Check if room is already empty
                    if (room.users.size === 0) {
                        destroyRoom(roomId, 'Room empty');
                    } else {
                        // Host left but others remain -> Start grace period
                        io.to(roomId).emit('system_message', `⚠️ HOST DISCONNECTED. Room will self-destruct in ${HOST_GRACE_PERIOD / 1000} seconds.`);
                        
                        room.destroyTimer = setTimeout(() => {
                            destroyRoom(roomId, 'Host failed to reconnect');
                        }, HOST_GRACE_PERIOD);
                    }
                } else if (room.users.size === 0) {
                    destroyRoom(roomId, 'Room empty');
                }
            }
        }
    });
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});

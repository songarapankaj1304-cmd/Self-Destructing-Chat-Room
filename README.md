# 🔐 Self-Destructing Chat Room

A secure real-time chat prototype focused on ephemeral communication and zero-retention architecture.

Messages exist only in memory and are automatically destroyed. No database is used. No chat history is stored. When a room ends, all data disappears.

This project demonstrates cybersecurity principles such as session lifecycle control, replay protection, abuse mitigation, and resource defense in a live Socket.io environment.

--------------------------------------------------

FEATURES

- Temporary chat rooms with unique IDs
- Memory-only message relay (no database)
- Automatic room destruction
- Host-controlled session lifecycle
- Self-destruct message architecture
- Optional password-protected rooms
- Replay attack protection (nonce tracking)
- Rate limiting & brute-force defense
- Connection abuse prevention
- Room & user caps
- Host disconnect grace timer
- XSS sanitization
- Helmet security headers
- Payload validation & size limits
- DoS resistance safeguards

--------------------------------------------------

SECURITY FOCUS

This prototype was built as a cybersecurity learning project and includes:

- Ephemeral system architecture
- Zero-knowledge message handling
- Memory cleanup enforcement
- Abuse-resistant socket design
- Resource exhaustion protection
- Defensive backend engineering
- Attack surface reduction

The server never writes messages to disk.
All communication is transient.

--------------------------------------------------

ARCHITECTURE OVERVIEW

Browser Client
↓
Socket.io
↓
Node.js Secure Relay Server
↓
Memory-only ephemeral rooms

Rooms are destroyed automatically when sessions end or time limits expire.

--------------------------------------------------

TECH STACK

- Node.js
- Express
- Socket.io
- Helmet
- Express-rate-limit
- UUID
- Crypto
- XSS sanitization

--------------------------------------------------

INSTALLATION

git clone <your-repo-link>
cd self-destruct-chat
npm install
node server.js

Open browser:
http://localhost:3000

--------------------------------------------------

SECURITY DISCLAIMER

This is a prototype for educational and cybersecurity research purposes only.

It is not intended for illegal use or production deployment.

Use responsibly.

--------------------------------------------------

LEARNING GOALS

- Secure real-time system design
- Ephemeral data handling
- Defensive backend engineering
- Threat modeling
- Abuse mitigation strategies
- Socket security architecture

--------------------------------------------------

LICENSE NOTICE

Unauthorized copying, redistribution, or claiming ownership of this project is prohibited.

See the LICENSE file for details.

--------------------------------------------------

AUTHOR

Pankaj Songara
Cybersecurity Project — Self-Destruct Communication System

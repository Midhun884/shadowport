# 🚀 shadowport

### Minimal Python TCP Tunnel for Secure Reverse Proxying

**shadowport** is a lightweight TCP tunnel system written in Python that allows you to expose private local services through a public server.

I built this to manage SSH and API access for **2000+ devices**, and it does exactly what it needs to do — small, fast, and reliable.

No complicated frameworks.  
No unnecessary layers.  
Just a simple tunnel that works.

---

## 🌐 How It Works

```
Private Network                     Public Server
─────────────────                  ─────────────────

 Local Service                      shadowport Server
 127.0.0.1:1194  ◄──────────────►   Public :1194

        ▲                                  ▲
        │                                  │
        │                                  │
   Your Device                       Remote Users

```

In simple terms:

1. A server runs on a machine with a public IP.
2. A client runs near your private service.
3. Users connect to the public server.
4. Traffic is forwarded securely back to your local service.
5. Raw TCP data flows between both sides.

Your service stays private.  
Your users get access.

Simple. Effective. Beautifully suspicious.

---

# ✨ Features

## Core Features

✅ TCP reverse tunneling  
✅ Public-to-private service forwarding  
✅ Raw TCP byte relay  
✅ SSH forwarding support  
✅ API panel exposure  
✅ Dashboard access  
✅ Private web service access  
✅ VPN-style TCP traffic support  

---

## Security

🔐 TLS encrypted client-server communication  
🔑 Token-based authentication  
🛡 AES-CFB protected control messages  
📜 Optional certificate verification support  

---

## Advanced Features

⚡ Automatic work connections  
⚡ Yamux TCP multiplexing support  
⚡ TOML configuration support  
⚡ Lightweight Python implementation  
⚡ One proxy registration per client  

---

# 📦 Project Structure

```
shadowport/
│
├── Server/
│   └── server.py        # Public tunnel server
│
├── Client/
│   └── client.py        # Local tunnel client
│
├── requirements.txt
│
└── README.md
```

---

# ⚡ Quick Start

## 1. Install Requirements

```bash
python -m pip install -r requirements.txt
```

---

# 2. Configure Client

Edit:

```
Client/client.py
```

Update:

```python
serverAddr = "YOUR_SERVER_IP"
serverPort = 7000
```

Set authentication:

```python
auth.token = "YOUR_SECRET_TOKEN"
```

Configure your proxy:

```python
name = "ssh_XQC24OG"
type = "tcp"

localIP = "127.0.0.1"
localPort = 1194

remotePort = 1194
```

---

# 3. Start Server

On your public server:

```bash
python Server/server.py
```

---

# 4. Start Client

Near your private service:

```bash
python Client/client.py
```

---

# 5. Connect

Example SSH access:

```bash
ssh user@your-server-ip -p 1194
```

Your private service is now reachable through the public server.

---

# ⚙️ Configuration

## Server Configuration

Location:

```
Server/server.py
```

Edit:

```
EMBEDDED_CONFIG

auth.token
```

---

## Client Configuration

Location:

```
Client/client.py
```

Available settings:

### Server

```text
serverAddr
serverPort
```

### Authentication

```text
auth.token
```

### Proxy

```text
name
type
localIP
localPort
remotePort
```

---

# 📝 TOML Configuration

You can load external configuration files:

```bash
python Client/client.py -c config.toml
```

Example:

```toml
serverAddr = "your-server-ip"
serverPort = 7000


[auth]
method = "token"
token = "your-secret"


[transport.tls]
enable = true


[[proxies]]

name = "ssh_tunnel"
type = "tcp"

localIP = "127.0.0.1"
localPort = 1194

remotePort = 1194
```

---

# 🔒 Security Notes

Keep your token private.

The token controls access to your tunnel.  
Anyone with the token can attempt to connect.

Use:

- Strong random tokens
- Firewall rules
- Restricted server ports
- TLS where possible

---

# 🔄 Connection Flow

```
Client
  |
  |  TLS Connection
  |
  ▼
Server Authentication
  |
  ▼
Proxy Registration
  |
  ▼
Remote User Connects
  |
  ▼
Server Requests Work Connection
  |
  ▼
Client Connects Local Service
  |
  ▼
TCP Traffic Relay
```

---

# 🛠 Possible Improvements

Want to extend shadowport?

Ideas:

- Multiple tunnels per client
- CLI arguments
- Better logging
- System services
- Docker support
- Health monitoring
- Web dashboard
- Metrics
- Automatic reconnect policies

---

# 🤝 Open Source

Built for people who need simple networking tools.

Use it. Modify it. Improve it.

Pull requests and ideas are welcome.

---

# 📜 License

Apache License 2.0

---

## ⭐ If shadowport helps you, consider giving it a star.

Happy tunneling 🚀

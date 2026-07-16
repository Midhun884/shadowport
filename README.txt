Midhun To The Opensource Community

I use this to handle SSH and API pages for over 2000 devices, and it works.

Midhun Link is a small Python TCP tunnel pair. One script runs on a public server. The other script runs near your private local service. Together they let remote users connect to a public port while the traffic is quietly carried back to your local machine.

In simple words

Your local service can stay at 127.0.0.1:1194.
The public server can listen on remote port 1194.
Users connect to the server.
The client opens work connections back to the server.
Raw TCP bytes are relayed both ways.
Everybody gets where they need to go. Beautiful. Suspiciously simple. We allow it.

What this can handle

TCP connectivity between a public server and a private local service.
TLS connections between client and server.
Yamux tcpMux mode for carrying the control stream when needed.
Token based authentication using the configured token.
One TCP proxy registration per running client.
Automatic work connections when a remote user connects.
Raw byte relay, so it can carry SSH, VPN style TCP traffic, web admin panels, API pages, dashboards, and other TCP services.
Optional TOML config loading with -c when the file follows the supported shape.

What is inside

Server/server.py starts the public listener and waits for clients.
Client/client.py connects to the server, logs in, registers one TCP proxy, and keeps the tunnel alive while the script is running.
requirements.txt lists the only external dependency.

Default proxy setup

Proxy name: ssh_XQC24OG
Remote port: 1194
Local target: 127.0.0.1:1194

If your local service runs somewhere else, change localIP and localPort in Client/client.py.
If you want the public side to use another port, change remotePort in Client/client.py.
If you want another proxy name, change name in Client/client.py.

Quick start

1. Install dependencies.

   python -m pip install -r requirements.txt

2. Edit the client config in Client/client.py.

   Set serverAddr to your server IP or domain.
   Set auth.token to the same token used by the server.
   Set name to your proxy name.
   Set localIP and localPort to the service running near the client.
   Set remotePort to the public port users should connect to.

3. Start the server.

   python Server/server.py

4. Start the client.

   python Client/client.py

5. Connect to the public server on the remote port.

   Example for SSH style traffic:

   ssh user@your-server-ip -p 1194

Configuration locations

Server token:

   Server/server.py
   EMBEDDED_CONFIG
   auth.token

Client token:

   Client/client.py
   EMBEDDED_CONFIG
   auth.token

Server address:

   Client/client.py
   EMBEDDED_CONFIG
   serverAddr

Server port:

   Client/client.py
   EMBEDDED_CONFIG
   serverPort

TLS:

   Client/client.py
   EMBEDDED_CONFIG
   transport.tls.enable

Set it to true to use TLS.
The server creates a temporary certificate when it starts.
The client accepts that certificate by default when no trusted CA file is configured.

Yamux tcpMux:

The client will try normal TCP first.
If needed, it also tries yamux mode automatically.
That means you usually do not need to touch anything.

Proxy details:

   Client/client.py
   EMBEDDED_CONFIG
   proxies

Inside the first proxy entry, edit:

   name
   type
   localIP
   localPort
   remotePort

Supported TOML config

You can load another config file with -c.

Example:

   python Client/client.py -c my-tunnel.toml

Supported shape:

   serverAddr = "your-server-ip"
   serverPort = 7000

   [auth]
   method = "token"
   token = "your-token"

   [transport.tls]
   enable = true

   [[proxies]]
   name = "ssh_XQC24OG"
   type = "tcp"
   localIP = "127.0.0.1"
   localPort = 1194
   remotePort = 1194

How the connection works

The client connects to the server.
The client uses TLS when TLS is enabled.
The client can use yamux tcpMux when the connection path needs it.
The client authenticates with the configured token.
The client logs in and receives a run ID.
The client registers one TCP proxy.
The server opens the remote public port.
When a remote user connects, the server asks the client for a work connection.
The client opens a work connection back to the server.
The client connects to the local target.
Both sides relay raw TCP bytes until the connection closes.

Encryption and authentication

TLS protects the socket between the client and server when enabled.
The control channel also uses AES-CFB with a key derived from your token.
The login request proves the client knows the token without sending the token as plain text.
Keep the token private. If someone gets it, they get invited to the party, and this is not that kind of party.

Important notes

Keep the server and client token the same. If they disagree, they will stare at each other like two people pulling a push door.

Use a remote port that is free. Ports already in use do not negotiate, they simply judge you.

Open the server firewall for the control port and the remote proxy port.

Run the server on a machine with a public IP or a reachable domain.

Run the client near the local service you want to expose.

This is intentionally small and readable. Fancy frameworks were not invited because the script already has a job and enough attitude.

Want to add more tools or features

Add more CLI options in Client/client.py and Server/server.py if you want less hardcoded config.
Add more config fields inside EMBEDDED_CONFIG if you want more defaults.
Add more proxy handling inside the proxies list if you want multiple tunnels.
Add logging if you want prettier output.
Add service files if you want it to run forever on Linux or Windows.
Add health checks if you enjoy knowing things before they explode.

No limits. Do whatever you want. Happy to help.

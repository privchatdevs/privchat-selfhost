# PrivChat Server (self-hosted)

Run your own [PrivChat](https://privchat.net) server. It hosts **one community** -
channels, members, and the media posted there - and none of that data touches
privchat.net. People will join it from the normal PrivChat app: **Add a server →
Join a 3rd-party server**, then paste your server's address. (The join flow
ships in an upcoming app update - you can host and prepare a server today.)

A community server is deliberately NOT a full platform: users' DMs, friend
lists, and group chats are personal social graph, processed and stored by each
user's home server - those APIs don't exist on this box at all. One instance
hosts exactly one community - that isn't configurable; want another community,
run another instance.

Full guide: https://privchat.net/docs (Self-hosting section)

## Requirements

- A machine that stays on - a VPS, a home server, or a spare PC (1 vCPU / 1 GB RAM is enough to start)
- **Node.js 22+** (or Docker)
- **A domain with HTTPS** is strongly recommended (e.g. `chat.yourdomain.net`).
  Browsers block the web app from connecting to plain `http://` or raw IPs, so a
  real certificate "just works" everywhere. Raw-IP servers can only be joined
  from the desktop app.
- A reverse proxy (nginx, Caddy, Traefik, or a tunnel) terminating TLS and
  forwarding to this app's port (default 4000), including WebSocket upgrades.

## Install & run

```bash
git clone https://github.com/FreeMoneyHyb/federation-distro.git
cd federation-distro/backend
npm ci
npm start
```

That's genuinely it. `npm ci` downloads the dependencies (the repo ships source
only). Then first boot auto-configures the basics: it generates the secrets
(session, at-rest field key, channel-message encryption key), detects your
VPS's public IP for `PUBLIC_URL`, and saves what it generated to
`data/auto-config.json` so restarts reuse the same values. To customize
anything, `cp .env.example .env` and edit - whatever you set there always wins.
The auto-detected IP works but is desktop-app-only and unencrypted; set
`PUBLIC_URL` to a real HTTPS domain as soon as you have one.

Or with Docker, from the repo root:

```bash
docker build -t privchat-server .
docker run -d --name privchat \
  -p 4000:4000 \
  -v /srv/privchat/data:/app/backend/data \
  --env-file backend/.env \
  privchat-server
```

On first boot the server creates its databases and its **federation signing
key** in the data folder.

## Configuration

Everything is set through `.env` (see [backend/.env.example](backend/.env.example)
for the full annotated list). Required:

| Variable | What it does |
| --- | --- |
| `PUBLIC_URL` | Full public address, e.g. `https://chat.yourdomain.net`. Used in invites, webhooks, and federation identity. A raw static IP works too (e.g. `http://203.0.113.10:4000`), but IP servers can only be joined from the desktop app, and plain `http` is unencrypted - fine for LAN/testing, not recommended on the open internet. |
| `SERVER_NAME` | The display name people see when they join. |
| `COOKIE_SECRET` | Session signing secret (32+ random bytes, base64). |
| `AES_256_KEY_BASE64` | At-rest field encryption key (exactly 32 bytes, base64). |

Optional: `DATA_DIR` (where everything lives - back it up), `S3_*`
(S3-compatible media storage; without it media uploads are disabled but chat
works), `SMTP_*` (verification emails; without it codes print to the console),
`HCAPTCHA_*` (captcha on registration), `FEDERATION=off` (fully private
standalone server).

## Moderation

There is no admin panel, on purpose: a self-hosted server is one community, and
you moderate it with the normal in-app owner tools - right-click a member to
kick or ban, and use roles/permissions like on any server. For network-level
blocking (an abusive IP range hammering your box), use your firewall or reverse
proxy, which sits in front of the app anyway.

## Federation & identity

PrivChat uses global identity: accounts live on their **home server** and keep
that identity when joining other servers. No passwords are ever shared between
servers.

- This server publishes its public signing key at `/api/federation/keys`; the
  private key never leaves your data folder.
- Other servers' users are verified through short-lived signed tokens checked
  against their home server's published key.
- Discovery info (name, version, key id) is served at `/api/federation/info`.

**Your domain is your identity, and ownership is verified.** Other servers only
trust keys they fetch from your claimed hostname themselves (DNS + TLS is the
ownership proof), so `PUBLIC_URL` must be an address you actually control -
claiming someone else's domain just produces an identity nobody will trust.
Shortly after every boot this server runs that same fetch against its own
`PUBLIC_URL` and logs the result: `Self-check passed` means your domain, DNS,
and proxy are wired correctly; a warning explains exactly what other servers
would see instead. (Behind NAT, "could not reach" can be a hairpinning false
alarm - confirm the address works from outside your network.)

**Back up your data folder.** It holds the databases AND the federation signing
key; losing the key means other servers stop trusting yours until they re-learn
the new one.

## Security notes

- Direct messages between users are end-to-end encrypted; this server only
  relays ciphertext. Channel messages can additionally be encrypted at rest
  with `SERVER_MSG_KEY_BASE64` - note you, the host, hold that key, so it
  protects against a stolen disk, not against you. Everything is TLS in
  transit either way.
- You, the host, are responsible for the data your server stores and for
  keeping the machine online, updated, and backed up.

## License

No license has been chosen yet - all rights reserved until one is added.

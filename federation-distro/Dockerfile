# PrivChat self-hosted server. Build from the repo root:
#   docker build -t privchat-server .
FROM node:22-alpine

WORKDIR /app

# Install backend dependencies first so Docker layer caching survives source edits.
COPY backend/package.json backend/package-lock.json ./backend/
RUN cd backend && npm ci --omit=dev

COPY backend ./backend

# Databases, uploads, and the federation signing key live here - mount a volume.
VOLUME /app/backend/data

ENV NODE_ENV=production
EXPOSE 4000

WORKDIR /app/backend
CMD ["node", "src/start.js"]

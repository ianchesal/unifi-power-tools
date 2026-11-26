FROM node:24-alpine AS builder
WORKDIR /app
COPY package*.json ./
COPY server/package.json server/package.json
COPY web/package.json web/package.json
RUN npm ci
COPY server ./server
COPY web ./web
RUN npm run build

FROM node:24-alpine AS deps
WORKDIR /app
COPY package*.json ./
COPY server/package.json server/package.json
RUN npm ci --omit=dev --workspace=server

FROM node:24-alpine
WORKDIR /app
RUN addgroup -S uptgroup && adduser -S uptuser -G uptgroup
COPY --from=deps /app/node_modules ./node_modules
COPY server/package.json ./server/package.json
COPY --from=builder /app/server/dist ./server/dist
COPY --from=builder /app/web/dist ./web/dist
# One data dir for both databases: events.db (syslog ingest) and lens.db
# (findings, triage queue, playbook).
RUN mkdir -p /data && chown uptuser:uptgroup /data
USER uptuser
# HTTP: dashboard, /api, /mcp, /health, /ready
EXPOSE 3002
# Syslog (CEF) from the UniFi gateway
EXPOSE 10514/udp
ENV EVENTS_DB_PATH=/data/events.db
ENV LENS_DB_PATH=/data/lens.db
# The container's network namespace is already the isolation boundary — bind
# to all interfaces here and control host exposure via how the ports are
# published (`-p 3002:3002` vs. `-p 127.0.0.1:3002:3002`).
ENV HOST=0.0.0.0
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD wget -qO- http://localhost:3002/health || exit 1
CMD ["node", "server/dist/index.js"]

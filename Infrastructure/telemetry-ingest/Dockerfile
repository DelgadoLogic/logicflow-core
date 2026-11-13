# LogicFlow telemetry ingest - Cloud Run image (Node 22, non-root, prod deps only)
FROM node:22-slim AS deps
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --omit=dev --no-audit --no-fund

FROM node:22-slim
ENV NODE_ENV=production \
    PORT=8080 \
    LF_STORAGE=gcs
WORKDIR /app
COPY --from=deps /app/node_modules ./node_modules
COPY package.json ./
COPY schema ./schema
COPY src ./src
# The image runs unprivileged; the FS emulator dir is never used with LF_STORAGE=gcs.
USER node
EXPOSE 8080
# HTTP service: node src/server.js   |   Cloud Run Job: node src/jobs/digest.js
CMD ["node", "src/server.js"]

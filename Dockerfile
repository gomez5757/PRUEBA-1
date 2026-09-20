FROM node:24-bookworm-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends git ca-certificates tar gzip util-linux \
 && rm -rf /var/lib/apt/lists/*
RUN npm install --global @openai/codex@0.155.0-alpha.9.2
WORKDIR /app
COPY server.mjs /app/server.mjs
ENV NODE_ENV=production
ENV CODEX_HOME=/root/.codex
EXPOSE 8080
CMD ["node", "/app/server.mjs"]

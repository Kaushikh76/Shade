# Shade relayer service. Non-root, healthchecked, no baked secrets.
FROM node:22-slim AS base
WORKDIR /app
COPY package.json package-lock.json* tsconfig.json ./
COPY packages ./packages
COPY apps/relayer ./apps/relayer
COPY apps/cli ./apps/cli
COPY db ./db
RUN npm install --no-audit --no-fund
RUN useradd -r -u 10001 shade && chown -R shade /app
USER shade
ENV NODE_ENV=production RELAYER_PORT=8082
EXPOSE 8082
HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
  CMD node -e "fetch('http://localhost:'+(process.env.RELAYER_PORT||8082)+'/health').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"
CMD ["npx","tsx","apps/relayer/src/server.ts"]

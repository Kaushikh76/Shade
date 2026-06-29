# Shade root-auditor service. Non-root, healthchecked, no baked secrets.
FROM node:22-slim AS base
WORKDIR /app
COPY package.json package-lock.json* tsconfig.json ./
COPY packages ./packages
COPY apps/root-auditor ./apps/root-auditor
COPY apps/cli ./apps/cli
COPY db ./db
RUN npm install --no-audit --no-fund
RUN useradd -r -u 10001 shade && chown -R shade /app
USER shade
ENV NODE_ENV=production ROOT_AUDITOR_PORT=8084
EXPOSE 8084
HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
  CMD node -e "fetch('http://localhost:'+(process.env.ROOT_AUDITOR_PORT||8084)+'/health').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"
CMD ["npx","tsx","apps/root-auditor/src/server.ts"]

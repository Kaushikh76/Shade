# Shade API service. Non-root, healthchecked, no baked secrets (env at runtime).
FROM node:22-slim AS base
WORKDIR /app
COPY package.json package-lock.json* tsconfig.json ./
COPY packages ./packages
COPY apps/api ./apps/api
COPY apps/cli ./apps/cli
COPY apps/prover ./apps/prover
COPY db ./db
RUN npm install --no-audit --no-fund
RUN useradd -r -u 10001 shade && chown -R shade /app
USER shade
ENV NODE_ENV=production API_PORT=8080
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
  CMD node -e "fetch('http://localhost:'+(process.env.API_PORT||8080)+'/health').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"
CMD ["npx","tsx","apps/api/src/server.ts"]

# Shade prover service. Needs node + snarkjs + circom artifacts + circom2soroban.
# NO private keys baked in. Circuit build outputs + the circom2soroban binary +
# coinutils must be mounted or built into the image at deploy; here we bring node
# + snarkjs (npm) and expect circuits/ + tools mounted via volume in compose.
FROM node:22-slim AS base
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/*
COPY package.json package-lock.json* tsconfig.json ./
COPY packages ./packages
COPY apps/prover ./apps/prover
COPY apps/cli ./apps/cli
COPY db ./db
RUN npm install --no-audit --no-fund && npm install -g snarkjs@0.7.6
RUN useradd -r -u 10001 shade && chown -R shade /app
USER shade
ENV NODE_ENV=production PROVER_PORT=8083
EXPOSE 8083
HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
  CMD node -e "fetch('http://localhost:'+(process.env.PROVER_PORT||8083)+'/health').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"
CMD ["npx","tsx","apps/prover/src/server.ts"]

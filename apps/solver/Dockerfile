# Shade solver service. Non-root, healthchecked, no baked secrets.
FROM node:22-slim AS base
WORKDIR /app
COPY package.json package-lock.json* tsconfig.json ./
COPY packages ./packages
COPY apps/solver ./apps/solver
COPY apps/cli ./apps/cli
COPY db ./db
RUN npm install --no-audit --no-fund
RUN useradd -r -u 10001 shade && chown -R shade /app
USER shade
ENV NODE_ENV=production SOLVER_PORT=8081
EXPOSE 8081
HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
  CMD node -e "fetch('http://localhost:'+(process.env.SOLVER_PORT||8081)+'/health').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"
CMD ["npx","tsx","apps/solver/src/server.ts"]

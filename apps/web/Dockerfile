# Shade web (Next.js). Production bundle; no server secrets baked in
# (only NEXT_PUBLIC_* are public). Non-root.
FROM node:22-slim AS build
WORKDIR /app
COPY apps/web/package.json apps/web/package-lock.json* ./apps/web/
COPY packages/note-vault ./packages/note-vault
WORKDIR /app/apps/web
RUN npm install --no-audit --no-fund
COPY apps/web ./
RUN npm run build

FROM node:22-slim AS run
WORKDIR /app/apps/web
ENV NODE_ENV=production
COPY --from=build /app/apps/web ./
COPY --from=build /app/packages ../../packages
RUN useradd -r -u 10001 shade && chown -R shade /app
USER shade
EXPOSE 3000
HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
  CMD node -e "fetch('http://localhost:3000').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"
CMD ["npm","run","start"]

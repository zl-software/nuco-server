# Multi stage build for the Nuco relay. Build with the parent folder as context so the
# shared protocol package (a sibling repo) is available:
#   docker build -f nuco-server/Dockerfile -t nuco-relay ..
# or use docker-compose.yml, which sets the context for you.
#
# A glibc base (bookworm-slim) is used so better-sqlite3 pulls a prebuilt binary with no
# compiler. On Alpine you would need to add build-base and python3 for a source build.

FROM node:24-bookworm-slim AS build

# Build the shared protocol package first.
WORKDIR /build/protocol
COPY protocol/package.json protocol/tsconfig.json ./
COPY protocol/src ./src
COPY protocol/PROTOCOL.md ./
RUN npm install && npm run build

# Build the relay. The file:../protocol dependency resolves to the package above.
WORKDIR /build/nuco-server
COPY nuco-server/package.json nuco-server/tsconfig.json ./
COPY nuco-server/src ./src
RUN npm install && npm run build

FROM node:24-bookworm-slim AS runtime
ENV NODE_ENV=production
COPY --from=build /build /app
WORKDIR /app/nuco-server
RUN useradd --create-home nuco && mkdir -p /data && chown -R nuco /app /data
USER nuco
EXPOSE 8787
CMD ["node", "dist/index.js"]

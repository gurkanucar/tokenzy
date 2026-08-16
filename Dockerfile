# syntax=docker/dockerfile:1

# ---- build ----
FROM golang:1.24-alpine AS build

WORKDIR /src

# Dependencies in their own layer so a source change does not refetch them.
COPY go.mod go.sum ./
RUN go mod download

COPY . .

# CGO off: modernc.org/sqlite is pure Go, so the result is a static binary.
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o /out/tokenzy .

# ---- runtime ----
FROM alpine:3.21

# Non-root user; /data belongs to it because SQLite writes there.
#
# The permissions on /data matter more here than in most services: the database
# under it holds tokens in plaintext, so 0700 keeps it to its owner even if
# something else ends up sharing the container.
RUN adduser -D -u 10001 tokenzy \
    && mkdir -p /data \
    && chown tokenzy:tokenzy /data \
    && chmod 700 /data

COPY --from=build /out/tokenzy /usr/local/bin/tokenzy

USER tokenzy
WORKDIR /data
VOLUME ["/data"]
EXPOSE 8080

# /healthz is a plain endpoint with no external dependencies.
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD wget -qO- http://127.0.0.1:8080/healthz || exit 1

ENTRYPOINT ["tokenzy"]
CMD ["serve", "-port", "8080", "-db", "/data/tokenzy.db"]

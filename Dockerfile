FROM golang:1.24-alpine AS build

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/proxybuff ./cmd/proxybuff


FROM alpine:3.20

RUN adduser -D -H -s /sbin/nologin proxybuff

COPY --from=build /out/proxybuff /proxybuff
COPY docker/entrypoint.sh /entrypoint.sh
COPY scripts/clear-cache.sh /usr/local/bin/proxybuff-clear-cache

RUN chmod +x /entrypoint.sh /usr/local/bin/proxybuff-clear-cache \
  && mkdir -p /etc/proxybuff /var/lib/proxybuff/cache \
  && chown -R proxybuff:proxybuff /etc/proxybuff /var/lib/proxybuff

ENV PROXYBUFF_CACHE_DIR=/var/lib/proxybuff/cache

USER proxybuff

EXPOSE 3128 443 80

ENTRYPOINT ["/entrypoint.sh"]


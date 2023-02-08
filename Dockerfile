FROM caddy:2-builder as builder
COPY . .
RUN xcaddy build --with github.com/silinternational/auth-proxy=./

FROM caddy:2
COPY --from=builder /usr/bin/caddy /usr/bin/caddy
COPY Caddyfile Caddyfile
CMD caddy run

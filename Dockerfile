FROM caddy:builder
COPY . .
ARG XCADDY_SKIP_CLEANUP=1
RUN xcaddy
CMD caddy

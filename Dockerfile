FROM caddy:builder
COPY . .
RUN source local.env
ARG XCADDY_SKIP_CLEANUP=1
RUN xcaddy
CMD caddy

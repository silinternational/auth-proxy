FROM caddy:builder
COPY . .
ARG ENVFILE="local.env"
RUN source ${ENVFILE}
ARG XCADDY_SKIP_CLEANUP=1
RUN xcaddy
CMD caddy

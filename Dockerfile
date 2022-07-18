FROM caddy:builder
COPY . .
RUN source local.env
CMD xcaddy run

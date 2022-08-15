# Auth Proxy

## Getting Started
This application is based on [Caddy Server](https://caddyserver.com/).

The only system requirement for running this application is Docker. Once the source is cloned, all you have to do to get
it running is:

1. Copy `local-example.env` to `local.env` and update values as described in the file. Secrets may be provided by
   another team member via Signal or other secure communication tool.
2. Run `make`

At this point you'll have a running instance of this application available at http://localhost:53060.

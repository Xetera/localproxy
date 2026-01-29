# Localproxy

`http://localhost:8080 -> https://project.proxy.localhost`

![](./showcase.jpg)

Programming is both my job and my hobby, and I have the convenience of using the same laptop for both. At work, the webservers in our monorepo use ports 3000-3005. And because we do a lot of testing with databases, I often end up having postgres running on the standard 5432 but also weird ones like, 5431, 5454, not knowing which instance exposes which port. At home, my own projects are an even bigger mess, running on 3030, 8080, 8081, 7000, you name it. I hate having to remember these random numbers.

Localproxy solves this problem for me. It runs envoy on port 80 and 443 with a self-signed certificate using [mkcert](https://github.com/FiloSottile/mkcert), and auto-discovers targets from both docker using `EXPOSE` fields and [labels](#docker-example-with-labels), and local processes listening to ports running directly under a given "projects" folder. To allow for non-browser tools to also function, the current running processes are also appended to `/etc/hosts` to make sure they point to 127.0.0.1, and are not resolved through external DNS. This is not already the default behavior on macos for some reason.

Localproxy supports proxying http(s), http/2, http/3 (QUIC) and TCP connections, provided TCP connections use TLS to allow determining the target domain. Otherwise that information is missing without a layer 7 protocol involved (ex: redis with `--tls --sni` and postgres with `?sslnegotiation=direct`)

Certain well-known ports on your computer are also checked to detect software you may have running locally outside your regular "projects" folder like syncthing, to also proxy connections there as well.

This project is currently WIP, so you'll have to install both `mkcer` and `envoy` and build the project from source using the following command. I've only tested this on macos so far but I plan for it to support any platform/architecture envoy supports.

```sh
sudo CGO_ENABLED=0 go run ./cmd/localproxyd --watch ~/myprojects
```

Then navigate to the dashboard https://proxy.localhost

#### Flags

- `--watch` Adds a folder to watch for processes. Only works with docker if not specified.
- `--https-redirect` Force https redirects for all created endpoints
- `--log-level` Log level for the envoy server. `error`, `info`, `debug`
- `--trace-process-logs` Show logs from external processes on the dashboard using dtrace on macOS. Requires disabling SIP. This WILL eventually lock up your system badly enough for you to hold down the power button for a restart [unless you're on Tahoe](https://news.ycombinator.com/item?id=45974681)

### Local process example

```sh
cd ~/myprojects/project1
# run a webserver on any port
npm run dev
# localproxy uses the path passed to --watch to
# automatically detect processes running in its sub-folders
curl https://project1.proxy.localhost
```

### Docker example with labels

Proxying traffic to docker containers works without exposing ports using `-p`. Instead you can use the following labels to configure the proxy behavior:

- `localproxy.subdomain` controls the [subdomain].proxy.internal domain
- `localproxy.port` 443/80 -> $port (used for webservers)
- `localproxy.tcpport` $tcpport -> $tcpport (used for for tcp servers that listen non non-web ports)

To allow reaching out to localproxy urls _from within_ containers, you need to use and map the alternative `.internal` tld to `host-gateway` using `--add-hosts`. `.localhost` specifically only points to 127.0.0.1 as per its RFC, which creates problems

##### Using docker run

```sh
docker run --add-host=test.proxy.internal:host-gateway alpine/curl https://test.proxy.internal
```

##### Using docker-compose

```yaml
services:
  curl:
    image: alpine/curl
    command: curl https://test.proxy.internal
    extra_hosts:
      - test.proxy.internal:host-gateway
```

#### Postgres

```sh
docker run --name postgres -l localproxy.tcpport=5432 -e POSTGRES_HOST_AUTH_METHOD=trust postgres
```

Two requirements for connection:

1. `sslmode` has to be `require` to not attempt a plaintext connection
2. `sslnegotiation` has to be `direct` to use TLS instead of STARTTLS

```sh
psql "postgresql://postgres@postgres.proxy.localhost/postgres?sslmode=require&sslnegotiation=direct"
```

#### Redis

```sh
docker run --name myredis -l localproxy.tcpport=6379 redis
```

Connect to it from the host without exposing ports. Sadly redis-cli doesn't seem to use the local trust chain on macos. You may be able to omit `--insecure` on other platforms.

```sh
redis-cli --tls --insecure -h myredis.proxy.localhost --sni myredis.proxy.localhost
# If you want to explicitly verify the certificate
redis-cli --tls --cacert "$(mkcert -CAROOT)/rootCA.pem" -h myredis.proxy.localhost --sni myredis.proxy.localhost
```

### Logs

By default localproxy tries to capture stdout logs from local processes as well as docker containers. However on macos this requires you to partially turn off SIP in recovery mode with

```sh
csrutil enable --without dtrace
```

If you're a yabai user, you'll want to combine this with the flags yabai requires. [Relevant documentation.](https://github.com/asmvik/yabai/wiki/Disabling-System-Integrity-Protection)

```sh
csrutil enable --without dtrace --without fs --without debug --without nvram
```

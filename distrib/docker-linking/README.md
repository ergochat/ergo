# Two-server linking test

From this directory, start both servers with:

```sh
docker compose up --build
```

The ports are published on all host IPv4 interfaces. Connect one IRC client to
`PUBLIC_IP:6667` and another to `PUBLIC_IP:6668`. The first server automatically
links to the second; joining the same channel from both clients exercises the
server-to-server link.

Both servers use a 4096-byte maximum line length and explicitly allow IRC
formatting characters and printable Unicode glyphs in identifiers such as
nicknames and channel names.

Make sure the host firewall or cloud security group allows inbound TCP traffic
on ports 6667 and 6668.

Stop the deployment and remove its temporary data with:

```sh
docker compose down -v
```

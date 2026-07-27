# rogg

A memory-safe, fast, observable routing stack written in Rust. It runs [AS4242423930](https://dn42.roggnetwork.com/) on dn42.

* **bgpgg** - BGP (Border Gateway Protocol) daemon
* **ggsh** - "gg shell" for managing rogg

## Features

- **Observable.** Native metrics as CloudWatch EMF, JSON, or Prometheus. No sidecar needed.
- **Programmable.** A gRPC API for peers, routes, and policy.
- **Memory-safe.** Written in Rust.
- **Operable.** ggsh shows and configures state, with commit and rollback.

## Get Started

Download the [latest release](https://github.com/roggnetwork/rogg/releases/latest) for your platform.

```bash
curl -LO https://github.com/roggnetwork/rogg/releases/download/<version>/rogg-<version>-x86_64-linux.tar.gz
tar xzf rogg-<version>-x86_64-linux.tar.gz
```

Create a config file:

```
# rogg.conf
service bgp {
  asn 65000
  router-id 1.1.1.1
  listen-addr 0.0.0.0:17900

  peer 192.168.1.1 {
    remote-as 65001
    port 17900
  }

  telemetry {
    cloudwatch-emf {
      namespace Rogg/Bgpgg
    }
    prometheus {
      listen 0.0.0.0:9273
    }
    json {}
  }
}
```

Start the daemon:

```bash
./bgpggd --config rogg.conf
```

Use **ggsh** to manage it:

```
$ ggsh
ggsh> show bgp summary
BGP router listening on 0.0.0.0:17900
RIB entries 1200, 2400 paths
Peers 2, 2 established

Neighbor             AS            MsgRcvd  MsgSent  State/PfxRcd
10.0.0.1             65001            4821     3200  Established

ggsh> show bgp routes
> 10.0.0.0/24
    via 10.0.0.1  lp 100  path 65001  [best]

ggsh> exit
```

For scripting: `ggsh show bgp summary`

### Other Ways

Build from source:

```bash
make
./target/release/bgpggd --config rogg.conf
./target/release/ggsh
```

Or use Docker:

```bash
curl -LO https://raw.githubusercontent.com/roggnetwork/rogg/master/bgpgg/docker/docker-compose.yml
docker compose up -d
docker exec rogg1 ggsh show bgp summary
```

## Docs

https://www.roggnetwork.com/doc

## License

Apache 2.0.

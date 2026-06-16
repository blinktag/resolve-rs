# resolve-rs

Implementation of a DNS resolver based on https://github.com/EmilHernvall/dnsguide
with some additional features, most importantly async.

### TODO

- [x] Safe shutdown
- [ ] Caching
- [ ] Tests
- [ ] TCP
- [ ] DNSSEC
- [x] Better error handling with `anyhow`
- [ ] Better logging with `tracing`
- [ ] API endpoints for metrics
- [ ] Zone Hosting 
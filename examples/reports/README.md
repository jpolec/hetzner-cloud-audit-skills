# Generated demo reports

Run `./scripts/demo.sh` to regenerate JSON, Markdown, SARIF, and the coverage ledger here.

`demo-cost-v0.3.json` and `demo-cost-v0.3.md` come from the synthetic `v0.3-cost` scenario. The headline reports EUR 90/month potential savings but EUR 0 confirmed: alternative candidates for one asset are not double-counted, and required RAM, owner-intent, and rollback evidence is deliberately absent.

`network-map.md` is different: it comes from a real 18-server Hetzner project, not a fixture, so `demo.sh` cannot regenerate it. Server names, public IP addresses, and administrative port numbers were replaced before rendering, and the file is refreshed by hand.

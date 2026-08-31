# grafana-observability

Grafana dashboards and the collection configuration that actually feeds them.

Most dashboards published on the internet arrive as a bare JSON file. You import
it, every panel says "No data", and you spend the afternoon working out which
exporter, which labels and which scrape config the author had running when they
took the screenshot. That missing half is the part worth publishing, so
everything here ships together: the dashboard, the collector configuration, the
queries, and the pitfalls that cost me time the first time round.

Everything is written to be reproduced somewhere other than where it was
written. No environment-specific identifiers, no host names, no topology. If a
technique only works in one estate it is not worth reading about, and it usually
is not worth doing either.

## Dashboards

| Dashboard | What it answers | Stack |
|---|---|---|
| [Kerberos RC4 Remediation](dashboards/kerberos-rc4/) | Who is still using RC4 in Active Directory, which accounts hold no AES key material, and what the KDC itself is already refusing | Alloy, Loki, LogQL |

## How this repository is laid out

```
dashboards/<name>/
  README.md                    what the dashboard answers, and what it needs
  build.py                     generates the dashboard JSON
  dashboard.json               import this into your own Grafana
  dashboard.grafana-com.json   the __inputs variant, for the public library
  alloy/                       collector configuration
  windows/ or linux/           anything that has to be turned on at the source
  screenshots/
docs/
  conventions.md               how every dashboard here is built
  importing.md                 importing, datasources, and the grafana.com trap
```

## The dashboards are generated, not hand-edited

Each dashboard has a `build.py` next to it, and that script is the source of
truth. The JSON is a build output.

This is on purpose. A 38-panel dashboard edited in the Grafana UI and exported
back produces a diff nobody can review, because the export reorders keys and
rewrites every panel. Generating it means a threshold change is three lines in
a diff, the same query is written once and reused, and the reasoning lives in
comments right next to the thing it explains.

```bash
cd dashboards/kerberos-rc4
python3 build.py                 # -> dashboard.json
python3 build.py --grafana-com   # -> dashboard.grafana-com.json
```

No dependencies beyond the Python standard library.

## Writing

Longer write-ups of most of this live at
[igorfasano.tech](https://igorfasano.tech). The articles cover the reasoning and
the failure modes; this repository carries the artefacts.

## Licence

MIT. Use them, change them, ship them. Attribution appreciated, not required.

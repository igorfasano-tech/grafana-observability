# Conventions

How every dashboard in this repository is built, so the next one looks like the
last one and you can guess where things are.

## The generator is the source of truth

Every dashboard directory has a `build.py`. The JSON next to it is output.

Edit the script, run it, commit both. Do not hand-edit the JSON, and do not
export from the Grafana UI and paste the result back: the export reorders keys
and rewrites panels, so the diff becomes unreviewable and the comments
explaining why a threshold is what it is are lost.

The scripts use the Python standard library only. No Jinja, no Grafonnet, no
build step. A single file you can read top to bottom is worth more than a
framework when somebody clones this in two years.

## Datasources

Panels reference `${DS_LOKI}` or `${DS_PROM}`, and that name is declared as a
**datasource template variable**, not as an `__inputs` entry.

The practical difference is that a variable can be changed from the dashboard
itself, so the same dashboard works against a self-hosted Loki and against
Grafana Cloud without re-importing. `__inputs` is resolved once at import time
and then frozen.

The exception is the public grafana.com library, which is built around
`__inputs`. See [importing.md](importing.md).

## Variables are scoped to streams that actually carry the data

An unscoped `label_values(job)` offers every job in the datasource. On Grafana
Cloud that means things like `integrations/oracledb` and `network/syslog`:
perfectly valid jobs, none of them carrying the events the dashboard needs, and
a guaranteed empty dashboard for anyone who picks the wrong one first.

Scope the variable to the selector the dashboard actually queries:

```
label_values({event_id=~"4768|4769|4771|20[1-9]"}, job)
```

## No data must not look like an all-clear

A stat panel with a green base threshold shows green when the answer is zero and
also when nothing is reporting at all. Those are opposite situations and one of
them is a broken pipeline.

Every stat here uses a neutral base step, an explicit green step at 0, and a
`noValue` of `not reporting`. Test both states before shipping: point the panel
at `vector(0)` for the healthy case, and at a selector that matches nothing for
the other.

## Cardinality

Labels are for things with a small, bounded set of values: event ID, host,
channel, job. Account names, service principal names, IP addresses and
encryption types are unbounded, and promoting them to labels multiplies the
stream count until ingestion falls over.

Parse those at query time instead. It is slower per query and dramatically
cheaper to run, and the queries in this repository are written that way
throughout.

## Stat panels aggregate, timeseries do not

- Stat: `sum(count_over_time(... [$__range]))`. Without `sum()` you get one
  value per stream and the panel renders a row of tiles instead of one number.
  `$__range` covers the whole selected window.
- Timeseries: `[$__interval]`, one point per step.

## Copy

Panel titles and descriptions say what the panel answers, in plain words, for
somebody who was not in the room when it was built. Section rows carry the
context. Anything that surprised me while building it goes in a comment in
`build.py`, not in my head.

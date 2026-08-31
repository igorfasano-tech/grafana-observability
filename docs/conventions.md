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

## Counting distinct values is the expensive one

`count(sum by (something) (...))` is how you count distinct values in LogQL, and
it is a trap. The inner aggregation has to materialise one series per distinct
value before the outer `count()` can reduce it to a number, so a panel counting
distinct service principals across a directory fails with:

```
maximum number of series (500) reached for a single query
```

That is `max_query_series`. It defaults to 500 and it is not raisable on Grafana
Cloud. There is no cheap distinct-count in LogQL to fall back on, no
approximation function, nothing.

So only count distinct values that are **bounded by the question**: domain
controllers, or accounts that appear on a remediation worklist, which is small
by the time somebody is looking at it. Counting distinct anything across the
whole estate will work in a lab and fail in production, which is the worst
possible time for it to fail.

When you catch yourself wanting an unbounded distinct count, ask what the panel
is really for. Usually it is a health check, and `sum(bytes_over_time(...))` or
`sum(count_over_time(...))` answers it in one series and tells you something
about the bill as well.

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

# Demo with simulated data

A local Loki and Grafana, preloaded with the dashboard and a week of invented
Kerberos telemetry. Useful for two things: seeing what the dashboard looks like
with data in it before you deploy anything, and taking screenshots without
putting a real domain's account names on the internet.

Everything here is fictional. The accounts, the services, the domain
controllers, the IP addresses and the numbers are all made up, and the domain is
`corp.example`.

## Running it

```bash
cd dashboards/kerberos-rc4/demo
docker compose up -d
python3 generate.py
```

Then open <http://localhost:3000>. It opens straight on the dashboard, no login,
because anonymous access is on and the login form is off. Set the time range to
**Last 7 days**.

The generator needs no packages. Python 3.9 or later, standard library only.

```bash
python3 generate.py --days 14          # a longer window
python3 generate.py --url http://...   # a Loki somewhere else
```

Tearing it down:

```bash
docker compose down -v
```

## The story the data tells

A domain part-way through RC4 remediation, which is the interesting state. Fully
clean is a boring screenshot and fully broken is not credible.

- About 97% AES adoption, with the RC4 line visibly falling across the week
- Seven accounts still receiving RC4 tickets, which is a worklist rather than a
  crowd
- Five service accounts with **no AES key material at all**. These need a
  password reset and nothing else will fix them.
- Four services where the account can do AES and the **client** is asking for
  RC4. Different worklist, different fix.
- One domain controller of four still advertising RC4 in
  `DCSupportedEncryptionTypes`
- Requests already failing with `KDC_ERR_ETYPE_NOTSUPP`, rising through the week
  as enforcement rolls out DC by DC
- KDC events 201 to 209 firing at a realistic rate, which is to say rarely.
  A handful a day plus one 205 per DC per boot. This is exactly why the
  dashboard defaults to a seven day window.

The seed is fixed, so the same run produces the same dashboard. Screenshots stay
comparable between takes.

## Before you screenshot

The dashboard header carries two placeholders on purpose:

- `YOUR LOGO`
- `Your Name` in the author badge

They live in the header panel in `../build.py`. Change them there and rerun
`python3 build.py`, then `docker compose restart grafana`.

For a clean capture, `?kiosk` on the URL removes the Grafana chrome:

```
http://localhost:3000/?kiosk&from=now-7d&to=now
```

## How the simulation works

`generate.py` writes the same line shape that Grafana Alloy produces: a JSON
object per event, carrying an `event_data` field with the raw
`<Data Name='...'>value</Data>` blob straight out of the Windows event XML, and
`job`, `computer`, `event_id` and `channel` as Loki labels.

That matters. The dashboard's queries do
`| json event_data="event_data" | line_format "{{.event_data}}" | regexp ...`,
so anything that gets the envelope wrong produces a dashboard that looks
plausible and answers nothing. Generating against the real shape means the demo
is a genuine test of the queries, not a mock-up of them.

Two details worth knowing if you adapt this:

**Loki rejects old samples by default.** Backfilling a week fails silently
against a stock configuration and you get an empty dashboard that looks like a
broken query. `loki.yaml` sets `reject_old_samples: false`.

**Entries are sorted per stream before pushing.** Loki accepts unordered writes
these days, but sorting keeps the push fast and the chunks tidy.

# Importing a dashboard

## Into your own Grafana

1. Dashboards, New, Import.
2. Upload `dashboard.json`, or paste its contents.
3. Pick your Loki (or Prometheus) datasource from the **Loki** dropdown at the
   top of the dashboard once it loads.

The datasource is a dashboard variable, so you can change it later without
re-importing, and you can point the same dashboard at a self-hosted Loki and at
Grafana Cloud from one browser tab.

If every panel says "No data" after import, work through these in order:

1. **Wrong datasource selected.** The variable defaults to the first Loki
   datasource alphabetically, which may not be the one holding your data.
2. **Wrong job selected.** The `Job` variable lists only jobs that carry the
   events the dashboard needs. If the dropdown is empty, nothing is arriving.
3. **The collector is not sending the labels the queries select on.** Check the
   `alloy/` directory for that dashboard. A collector that ships the events
   without promoting the labels produces data that is present in Loki and
   invisible to `{event_id="4768"}`.
4. **URL parameters overriding your selection.** A URL carrying
   `?var-DS_LOKI=...&var-job=` will override the saved defaults, including with
   an empty value. Open the dashboard from the dashboard list, not from a link
   somebody sent you.

## Publishing to grafana.com

The public dashboard library does not accept the file above, and it fails
quietly: you upload, and nothing happens. No error, no message.

The reason is `__inputs`. The grafana.com importer reads that block to build the
"select your datasource" step, and a dashboard that declares a datasource
*variable* instead has no such block. The form validates, finds nothing it
recognises, and stops.

Use the other build:

```bash
python3 build.py --grafana-com   # -> dashboard.grafana-com.json
```

That variant moves `DS_LOKI` out of `templating` and into `__inputs`. Everything
else is identical, and panels keep referencing `${DS_LOKI}` either way.

You cannot declare both. Grafana will prompt for the input at import time and
then ignore what you chose, because the variable wins.

Other things the uploader is quiet about:

- `"id"` must be `null`. An exported dashboard carries the numeric id it had in
  your Grafana, and the upload is rejected with it present.
- `__requires` should list the panel plugin types you actually use, so the
  library can warn people on older Grafana versions.
- The `uid` should be stable across versions. It is what keeps an updated
  dashboard attached to the same listing.

#!/usr/bin/env python3
"""
Kerberos RC4 Remediation dashboard - portable / community edition.

Same layout language as a polished internal dashboard (branded header,
emoji section rows, info cards, worklist tables) but:
  * one datasource only: Loki, fed by Grafana Alloy
  * no vendor branding - a clearly marked "YOUR LOGO" placeholder
  * no environment-specific identifiers of any kind
"""
import argparse, copy, json, pathlib

DS = "${DS_LOKI}"

# --- LogQL building blocks -------------------------------------------------
SEL    = '{job="$job", computer=~"$dc", event_id=~"4768|4769"}'
SEL69  = '{job="$job", computer=~"$dc", event_id="4769"}'
SEL71  = '{job="$job", computer=~"$dc", event_id="4771"}'
# Kdcsvc 201-209 land in the System channel, so channel= disambiguates them
# from anything else that happens to use those IDs.
SELKDC = '{job="$job", computer=~"$dc", channel="System", event_id=~"20[1-9]"}'
# Every event ID this dashboard knows about, used to scope the variables.
KERB_IDS = "4768|4769|4771|20[1-9]"
# 205 is a start-up configuration finding, not a per-request warning, and it
# gets its own stat. Keeping it out of here stops it double-counting.
KDC_WARN  = '{job="$job", computer=~"$dc", channel="System", event_id=~"201|202|206|207"}'
KDC_BLOCK = '{job="$job", computer=~"$dc", channel="System", event_id=~"203|204|208|209"}'

RX = {
    "etype":        "`<Data Name='TicketEncryptionType'>(?P<etype>[^<]*)</Data>`",
    "svc_keys":     "`<Data Name='ServiceAvailableKeys'>(?P<svc_keys>[^<]*)</Data>`",
    "svc_set":      "`<Data Name='ServiceSupportedEncryptionTypes'>(?P<svc_set>[^<]*)</Data>`",
    "dc_set":       "`<Data Name='DCSupportedEncryptionTypes'>(?P<dc_set>[^<]*)</Data>`",
    "service":      "`<Data Name='ServiceName'>(?P<service>[^<]*)</Data>`",
    "account":      "`<Data Name='TargetUserName'>(?P<account>[^<]*)</Data>`",
    "client_ip":    "`<Data Name='IpAddress'>(?P<client_ip>[^<]*)</Data>`",
    "status":       "`<Data Name='Status'>(?P<status>[^<]*)</Data>`",
    "client_etype": "`<Data Name='ClientAdvertizedEncryptionTypes'>(?P<client_etypes>[^<]*)</Data>`",
}

# NOTE: the stored Loki line is Go-encoded JSON, so '<' and '>' arrive as
# \u003c / \u003e. A line filter containing angle brackets matches NOTHING.
# Prefilter on a bare field name, then json -> line_format -> regexp.
def pipe(*keys):
    s = ' | json event_data="event_data" | line_format "{{.event_data}}"'
    for k in keys:
        s += " | regexp " + RX[k]
    return s

def q(sel, prefilter, keys, extra=""):
    return sel + ' |= "' + prefilter + '"' + pipe(*keys) + extra

RC4     = ' | etype=~"0x17|0x18"'
AES     = ' | etype=~"0x11|0x12"'
# NOTE the svc_keys!="-" filter. Events where the field is not applicable carry a
# literal "-", which passes "not empty", "not N/A" and "contains no AES" - so without
# it krbtgt and friends show up as accounts needing a password reset. False positives,
# and the kind that gets someone to reset twelve service accounts for nothing.
NO_AES  = ' | svc_keys!="" | svc_keys!="N/A" | svc_keys!="-" | svc_keys!~".*AES.*"'

# --- panel helpers ---------------------------------------------------------
def tgt(expr, ref="A", instant=False, legend=""):
    t = {"datasource": {"type": "loki", "uid": DS}, "editorMode": "code",
         "expr": expr, "refId": ref, "queryType": "instant" if instant else "range"}
    if instant:
        t["instant"] = True
    if legend:
        t["legendFormat"] = legend
    return t

def stat(pid, title, desc, expr, x, y, w=4, h=4, steps=None, unit="none", dec=0,
         no_value=None, color_mode="background"):
    # no_value matters wherever "no events" and "zero events" mean different things.
    # Left alone, an absent series takes the base threshold colour, so a panel with
    # nothing behind it renders as a green all-clear. See NODATA below.
    defaults = {"color": {"mode": "thresholds"}, "decimals": dec,
        "thresholds": {"mode": "absolute", "steps": steps or [{"color": "text", "value": None}]},
        "unit": unit}
    if no_value is not None:
        defaults["noValue"] = no_value
    return {"id": pid, "type": "stat", "title": title, "description": desc,
        "datasource": {"type": "loki", "uid": DS},
        "gridPos": {"h": h, "w": w, "x": x, "y": y},
        "fieldConfig": {"defaults": defaults, "overrides": []},
        "options": {"colorMode": color_mode, "graphMode": "none", "justifyMode": "auto",
            "orientation": "auto", "percentChangeColorMode": "standard",
            "reduceOptions": {"calcs": ["lastNotNull"], "fields": "", "values": False},
            "showPercentChange": False, "textMode": "auto", "wideLayout": True},
        "targets": [tgt(expr)]}

def ts(pid, title, desc, targets, x, y, w=12, h=8, stack=True):
    return {"id": pid, "type": "timeseries", "title": title, "description": desc,
        "datasource": {"type": "loki", "uid": DS},
        "gridPos": {"h": h, "w": w, "x": x, "y": y},
        "fieldConfig": {"defaults": {"color": {"mode": "palette-classic"},
            "custom": {"axisBorderShow": False, "axisPlacement": "auto", "barAlignment": 0,
                "drawStyle": "bars", "fillOpacity": 70, "gradientMode": "none", "lineWidth": 0,
                "pointSize": 5, "showPoints": "never", "spanNulls": False,
                "stacking": {"group": "A", "mode": "normal" if stack else "none"}},
            "min": 0, "unit": "none"}, "overrides": []},
        "options": {"legend": {"calcs": ["sum"], "displayMode": "table",
            "placement": "bottom", "showLegend": True},
            "tooltip": {"mode": "multi", "sort": "desc"}},
        "targets": targets}

def table(pid, title, desc, expr, x, y, w=24, h=8, rename=None, overrides=None, sort=None):
    return {"id": pid, "type": "table", "title": title, "description": desc,
        "datasource": {"type": "loki", "uid": DS},
        "gridPos": {"h": h, "w": w, "x": x, "y": y},
        "fieldConfig": {"defaults": {"color": {"mode": "thresholds"},
            "custom": {"align": "auto", "cellOptions": {"type": "auto"},
                       "filterable": True, "inspect": False},
            "thresholds": {"mode": "absolute", "steps": [{"color": "text", "value": None}]}},
            "overrides": overrides or []},
        "options": {"cellHeight": "sm", "showHeader": True,
            "footer": {"countRows": False, "enablePagination": True, "fields": "",
                       "reducer": ["sum"], "show": False},
            "sortBy": [{"desc": True, "displayName": sort}] if sort else []},
        "targets": [tgt(expr, instant=True)],
        "transformations": [{"id": "organize", "options": {
            "excludeByName": {"Time": True},
            "indexByName": _order(rename), "renameByName": _rename(rename)}}]}

# Grafana names the value field of an instant Loki query either "Value" or
# "Value #A" depending on how it disambiguates the frame. renameByName matches on
# the exact current name, so mapping only "Value" silently misses and the raw
# header leaks through - taking the panel's sortBy down with it, since that
# references the renamed display name.
def _rename(rename):
    r = dict(rename or {})
    if "Value" in r:
        r["Value #A"] = r["Value"]
    return r

def _order(rename):
    keys = [k for k in (rename or {}) if k != "Value"]
    idx = {k: i for i, k in enumerate(keys)}
    idx["Value #A"] = len(keys)
    idx["Value"] = len(keys) + 1
    return idx

def logs(pid, title, desc, expr, x, y, w=24, h=10):
    return {"id": pid, "type": "logs", "title": title, "description": desc,
        "datasource": {"type": "loki", "uid": DS},
        "gridPos": {"h": h, "w": w, "x": x, "y": y},
        "options": {"dedupStrategy": "none", "enableLogDetails": True, "prettifyLogMessage": False,
            "showCommonLabels": False, "showLabels": False, "showTime": True,
            "sortOrder": "Descending", "wrapLogMessage": True},
        "targets": [tgt(expr)]}

def text(pid, content, x, y, w, h, transparent=True):
    return {"id": pid, "type": "text", "title": "", "transparent": transparent,
        "datasource": {"type": "datasource", "uid": "-- Dashboard --"},
        "gridPos": {"h": h, "w": w, "x": x, "y": y},
        "options": {"code": {"language": "html", "showLineNumbers": False, "showMiniMap": False},
                    "content": content, "mode": "html"}, "targets": []}

def row(pid, title, y):
    return {"id": pid, "type": "row", "title": title, "collapsed": False,
            "gridPos": {"h": 1, "w": 24, "x": 0, "y": y}, "panels": []}

# --- header ---------------------------------------------------------------
# The logo slot is a clearly-marked placeholder. To brand this dashboard,
# replace the <div id="logo-slot"> block below with your own <img> tag.
WINDOWS_LOGO = ("https://upload.wikimedia.org/wikipedia/commons/thumb/5/5f/"
                "Windows_logo_-_2012.svg/120px-Windows_logo_-_2012.svg.png")

HEADER = (
 '<div style="display:flex;align-items:center;justify-content:space-between;'
 'background:linear-gradient(135deg,#0d1117 0%,#161b22 50%,#1a2332 100%);border-radius:12px;'
 'padding:16px 28px;border:1px solid #30363d;box-shadow:0 4px 24px rgba(0,0,0,0.4)">'
   '<div style="display:flex;align-items:center;gap:20px">'
     # ---- replace this block with <img src="YOUR_LOGO_URL" style="height:50px" /> ----
     '<div id="logo-slot" style="display:flex;align-items:center;justify-content:center;'
     'height:50px;min-width:130px;border:2px dashed #484f58;border-radius:10px;'
     'color:#8b949e;font-size:12px;font-weight:700;letter-spacing:1.5px;'
     'text-transform:uppercase;padding:0 14px">Your&nbsp;Logo</div>'
     # ------------------------------------------------------------------------------
     '<div style="width:1px;height:40px;background:rgba(48,54,61,0.9)"></div>'
     '<img src="' + WINDOWS_LOGO + '" alt="Windows" style="height:30px;filter:brightness(1.1)" '
     'onerror="this.style.display=\'none\'" />'
     '<div>'
       '<div style="font-size:22px;font-weight:700;color:#e6edf3;letter-spacing:0.5px">'
       'Active Directory | Kerberos RC4 Remediation</div>'
       '<div style="font-size:12px;color:#8b949e;margin-top:4px">'
       'CVE-2026-20833 &bull; Security 4768 / 4769 + Kdcsvc 201-209 &bull; continuous RC4 exposure, '
       'not a point-in-time export</div>'
     '</div>'
   '</div>'
   '<div style="display:flex;gap:16px;align-items:center">'
     '<div style="text-align:center;padding:8px 16px;background:rgba(56,139,253,0.1);'
     'border:1px solid rgba(56,139,253,0.3);border-radius:8px">'
       '<div style="font-size:10px;color:#8b949e;text-transform:uppercase;letter-spacing:1px">Source</div>'
       '<div style="font-size:13px;color:#58a6ff;font-weight:600;margin-top:2px">Grafana Alloy &rarr; Loki</div></div>'
     '<div style="text-align:center;padding:8px 16px;background:rgba(210,153,34,0.1);'
     'border:1px solid rgba(210,153,34,0.3);border-radius:8px">'
       '<div style="font-size:10px;color:#8b949e;text-transform:uppercase;letter-spacing:1px">Version</div>'
       '<div style="font-size:13px;color:#d29922;font-weight:600;margin-top:2px">1.0</div></div>'
     '<div style="text-align:center;padding:8px 16px;background:rgba(63,185,80,0.1);'
     'border:1px solid rgba(63,185,80,0.3);border-radius:8px">'
       '<div style="font-size:10px;color:#8b949e;text-transform:uppercase;letter-spacing:1px">Author</div>'
       '<div style="font-size:13px;color:#3fb950;font-weight:600;margin-top:2px">Your&nbsp;Name</div></div>'
   '</div>'
 '</div>')

def card(accent, emoji, title, tcolor, body):
    # No coloured left rail and no gradient. The category reads from a small
    # dot next to the heading; everything else is spacing and type weight, so
    # four of these side by side look like one object rather than four ribbons.
    return ('<div style="background:#12161c;border:1px solid #262c36;border-radius:10px;'
            'padding:20px 22px;font-family:system-ui;height:100%;box-sizing:border-box">'
            '<div style="display:flex;align-items:center;gap:9px;margin-bottom:11px">'
            '<span style="width:6px;height:6px;border-radius:50%;background:' + accent + ';'
            'flex:0 0 auto"></span>'
            '<span style="font-size:11px;font-weight:600;letter-spacing:0.9px;'
            'text-transform:uppercase;color:#8b949e">' + title + '</span></div>'
            '<div style="color:#c9d1d9;font-size:12.5px;line-height:1.7">' + body + '</div></div>')

CARD_WHY = card("#ff6b6b", "&#128737;", "Why this exists", "#ff7b72",
 "Microsoft is removing RC4 as the default supported encryption type for AD domain controllers "
 "(<b>CVE-2026-20833</b>). Windows Server 2025 DCs already refuse to issue RC4 TGTs.<br/><br/>"
 "The documented remediation path is a point-in-time PowerShell audit. A service account that "
 "authenticates <b>once a month</b> over RC4 is not in that snapshot, and it breaks the day "
 "enforcement lands. RC4 removal is a <b>continuous monitoring</b> problem.")

CARD_ETYPE = card("#d29922", "&#128273;", "Reading encryption types", "#ffa657",
 "<code>0x12</code> AES256-CTS-HMAC-SHA1-96, good<br/>"
 "<code>0x11</code> AES128-CTS-HMAC-SHA1-96, good<br/>"
 "<code>0x17</code> RC4-HMAC, <b style='color:#f85149'>remove</b><br/>"
 "<code>0x18</code> RC4-HMAC-EXP, <b style='color:#f85149'>remove</b><br/>"
 "<code>0x1</code> / <code>0x3</code> DES, <b style='color:#f85149'>remove</b><br/>"
 "<code>0xffffffff</code> no ticket issued (request failed)<br/><br/>"
 "<b>Not the same thing</b> as the <code>msDS-SupportedEncryptionTypes</code> bitmask, where "
 "<code>0x18</code> means AES128 plus AES256, the opposite meaning.")

CARD_DATA = card("#58a6ff", "&#128225;", "Where the data comes from", "#79c0ff",
 "A single stream: Windows Security events <b>4768</b> (TGT) and <b>4769</b> (service ticket), "
 "collected by <b>Grafana Alloy</b> and stored in <b>Loki</b>.<br/><br/>"
 "Since the November 2022 updates, these events carry <code>ServiceAvailableKeys</code>, "
 "<code>ServiceSupportedEncryptionTypes</code>, <code>ClientAdvertizedEncryptionTypes</code> and "
 "<code>DCSupportedEncryptionTypes</code>, enough to answer every question below from "
 "<b>one</b> datasource, with no agent on the clients and no scheduled script.")

CARD_FIX = card("#3fb950", "&#128736;", "Remediation guide - one object at a time", "#7ee787",
 "<b style='color:#f85149'>No AES keys</b> (Available Keys shows RC4 only): the account physically "
 "cannot do AES &rarr; <b>reset the account password</b> to generate AES key material. The password "
 "value does not have to change. Then set <code>msDS-SupportedEncryptionTypes = 24</code> "
 "(<code>0x18</code>).<br/><br/>"
 "<b style='color:#d29922'>Client negotiating RC4</b>: the service already has AES; the listed "
 "client IPs advertise no AES &rarr; enable AES on those clients via GPO "
 "<i>Network security: Configure encryption types allowed for Kerberos</i>. On Java and SAP hosts "
 "the cause is <code>C:\\Windows\\krb5.ini</code> carrying <code>rc4-hmac</code> in "
 "<code>default_tkt_enctypes</code>; the JVM reads it at startup, so <b>restart the service</b> "
 "after editing.<br/><br/>"
 "<b style='color:#58a6ff'>DC posture</b>: once dependent objects are clean, set "
 "<code>DefaultDomainSupportedEncTypes = 0x18</code> on the KDC. A service that genuinely needs "
 "RC4 gets a scoped <code>msDS-SET = 0x24</code> instead.<br/><br/>"
 "<span style='color:#8b949e'>Failure signature after enforcement: "
 "<code>KRB_AP_ERR 0xE KDC_ERR_ETYPE_NOTSUPP</code>, <code>klist 0xc00002fd</code>.</span>")

# --- thresholds ------------------------------------------------------------
RED   = [{"color": "green", "value": None}, {"color": "red", "value": 1}]
ORNG  = [{"color": "green", "value": None}, {"color": "orange", "value": 1}]
NEUT  = [{"color": "text", "value": None}]
PCT   = [{"color": "red", "value": None}, {"color": "orange", "value": 95}, {"color": "green", "value": 99.9}]
# Base step neutral, so an absent series is grey rather than green. The explicit
# step at 0 is what makes a genuine zero read as healthy.
RED0  = [{"color": "text", "value": None}, {"color": "green", "value": 0}, {"color": "red", "value": 1}]
ORNG0 = [{"color": "text", "value": None}, {"color": "green", "value": 0}, {"color": "orange", "value": 1}]
NODATA = "not reporting"

P = []
# ---------------- header ----------------
P.append(text(999, HEADER, 0, 0, 24, 4))

# ---------------- overview ----------------
P.append(row(1000, "\U0001F4CA Overview", 4))
P.append(stat(101, "RC4 Tickets Issued",
    "Tickets the KDC still encrypted with RC4 (0x17 / 0x18). Target is zero.",
    'sum(count_over_time(' + q(SEL, "TicketEncryptionType", ["etype"], RC4) + ' [$__range]))',
    0, 5, 4, 4, RED0, no_value=NODATA, color_mode="value"))
P.append(stat(102, "Accounts Using RC4",
    "Distinct requesting accounts that received at least one RC4 ticket in range. Counting distinct values needs one series per account, so on a large estate at the start of remediation this can hit Loki max_query_series (500 by default). Narrow the range if it does.",
    'count(sum by (account) (count_over_time(' + q(SEL, "TicketEncryptionType", ["etype", "account"], RC4) + ' [$__range])))',
    4, 5, 4, 4, RED0, no_value=NODATA, color_mode="value"))
P.append(stat(103, "Services Without AES Keys",
    "Distinct services whose Available Keys field holds no AES key material. Remediation is a password reset.",
    'count(sum by (service) (count_over_time(' + q(SEL, "ServiceAvailableKeys", ["svc_keys", "service"], NO_AES) + ' [$__range])))',
    8, 5, 4, 4, RED0, no_value=NODATA, color_mode="value"))
P.append(stat(104, "ETYPE_NOTSUPP Failures",
    "Event 4769 with failure code 0xE - client and service could not agree an encryption type. These are already broken.",
    'sum(count_over_time(' + q(SEL69, "TicketEncryptionType", ["status"], ' | status="0xe"') + ' [$__range]))',
    12, 5, 4, 4, RED0, no_value=NODATA, color_mode="value"))
P.append(stat(105, "AES Adoption",
    "Share of issued tickets using AES128 or AES256, out of all tickets that produced an encryption type. Target is 100%.",
    'sum(count_over_time(' + q(SEL, "TicketEncryptionType", ["etype"], AES) + ' [$__range])) / '
    'sum(count_over_time(' + q(SEL, "TicketEncryptionType", ["etype"], ' | etype!="" | etype!="0xffffffff"') + ' [$__range])) * 100',
    16, 5, 4, 4, PCT, unit="percent", dec=2, no_value=NODATA, color_mode="value"))
P.append(stat(106, "Domain Controllers Reporting",
    "Collection health. Compare against the number of DCs you expect to be shipping events - a drop here means blind spots, not good news.",
    'count(sum by (computer) (count_over_time(' + SEL + ' [$__range])))',
    20, 5, 4, 4, NEUT, no_value="0"))

P.append(text(1, CARD_WHY,   0, 9, 8, 7))
P.append(text(2, CARD_ETYPE, 8, 9, 8, 7))
P.append(text(3, CARD_DATA, 16, 9, 8, 7))

# ---------------- service accounts ----------------
P.append(row(1001, "\U0001F511 Service Accounts and Key Material", 16))
P.append(table(301, "Services Without AES Key Material - Remediation Worklist",
    "One row equals one account to fix. Available Keys with no AES entry means the account cannot negotiate AES at all. "
    "Remediation is a password reset to generate AES keys, then msDS-SupportedEncryptionTypes = 24. An empty table is the healthy state.",
    'sum by (service, svc_keys, svc_set) (count_over_time(' + q(SEL, "ServiceAvailableKeys", ["svc_keys", "svc_set", "service"], NO_AES) + ' [$__range]))',
    0, 17, 24, 8,
    rename={"service": "Service", "svc_keys": "Available Keys",
            "svc_set": "msDS-SupportedEncryptionTypes", "Value": "Events"},
    sort="Events"))

P.append(ts(201, "Tickets by Encryption Family",
    "Stacked ticket volume by encryption family. The RC4 band reaching zero and staying there is the definition of done.",
    [tgt('sum(count_over_time(' + q(SEL, "TicketEncryptionType", ["etype"], AES) + ' [$__interval]))', "A", legend="AES (0x11 / 0x12)"),
     tgt('sum(count_over_time(' + q(SEL, "TicketEncryptionType", ["etype"], RC4) + ' [$__interval]))', "B", legend="RC4 (0x17 / 0x18)"),
     tgt('sum(count_over_time(' + q(SEL, "TicketEncryptionType", ["etype"], ' | etype=~"0x1|0x3"') + ' [$__interval]))', "C", legend="DES (0x1 / 0x3)"),
     tgt('sum(count_over_time(' + q(SEL, "TicketEncryptionType", ["etype"], ' | etype="0xffffffff"') + ' [$__interval]))', "D", legend="No ticket issued")],
    0, 25, 12, 8))
P.append(ts(202, "RC4 Tickets by Domain Controller",
    "Which DCs are still serving RC4. Often a single site or one legacy application server is behind the whole number.",
    [tgt('sum by (computer) (count_over_time(' + q(SEL, "TicketEncryptionType", ["etype"], RC4) + ' [$__interval]))', "A", legend="{{computer}}")],
    12, 25, 12, 8))

# ---------------- client side ----------------
P.append(row(1002, "\u2615 Client-Side Fixes (Java, SAP, appliances)", 33))
P.append(table(303, "Clients Advertising No AES - The Fix Belongs On The Client",
    "The client machine advertised an encryption type list containing no AES. The service may already be AES-capable; "
    "the negotiation is being dragged down by the client. On Java and SAP hosts, look at krb5.ini.",
    'sum by (service, client_ip, client_etypes) (count_over_time(' + q(SEL, "ClientAdvertizedEncryptionTypes", ["client_etype", "service", "client_ip"], ' | client_etypes!="" | client_etypes!="-" | client_etypes!~".*AES.*"') + ' [$__range]))',
    0, 34, 14, 8,
    rename={"service": "Service", "client_ip": "Client IP",
            "client_etypes": "Advertised Etypes", "Value": "Events"},
    sort="Events"))
P.append(text(4, CARD_FIX, 14, 34, 10, 8, transparent=False))

# ---------------- ticket failures ----------------
P.append(row(1003, "\U0001F3AB Ticket Failures", 42))
P.append(table(304, "Failing Now - KDC_ERR_ETYPE_NOTSUPP (0xE)",
    "Already broken today. Invisible in the KDC audit events, and usually masked by an NTLM fallback that makes the "
    "application look healthy while silently downgrading the authentication.",
    'sum by (service, account, client_ip) (count_over_time(' + q(SEL69, "TicketEncryptionType", ["status", "service", "account", "client_ip"], ' | status="0xe"') + ' [$__range]))',
    0, 43, 24, 8,
    rename={"service": "Service", "account": "Requesting Account",
            "client_ip": "Client IP", "Value": "Failures"},
    sort="Failures"))
P.append(table(302, "RC4 Tickets by Service, Account and Client",
    "Every RC4 ticket still being issued, attributed to the requesting account and the client IP that asked for it. "
    "This is the list you work down.",
    'sum by (service, account, client_ip, etype) (count_over_time(' + q(SEL, "TicketEncryptionType", ["etype", "service", "account", "client_ip"], RC4) + ' [$__range]))',
    0, 51, 24, 9,
    rename={"service": "Service", "account": "Requesting Account", "client_ip": "Client IP",
            "etype": "Ticket Etype", "Value": "Tickets"},
    sort="Tickets"))

# ---------------- domain controllers ----------------
P.append(row(1004, "\U0001F5A5 Domain Controller Posture", 60))
P.append(stat(401, "DCs Advertising RC4",
    "Domain controllers whose DCSupportedEncryptionTypes still includes RC4. Target after cleanup is 0x18 (AES only).",
    'count(sum by (computer) (count_over_time(' + q(SEL, "DCSupportedEncryptionTypes", ["dc_set"], ' | dc_set!="-" | dc_set=~".*RC4.*"') + ' [$__range])))',
    0, 61, 6, 4, ORNG0, no_value=NODATA, color_mode="value"))
P.append(stat(402, "Ticket Events Collected",
    "Total 4768 / 4769 events ingested in range. A sudden drop usually means a broken bookmark or a stopped collector, not a quiet estate.",
    'sum(count_over_time(' + SEL + ' [$__range]))',
    6, 61, 6, 4, NEUT, unit="short", no_value="0"))
# This used to be "Distinct Services Seen", as count(sum by (service) (...)).
# It broke on a real estate with "maximum number of series (500) reached for a
# single query". LogQL has no cheap distinct-count: sum by (service) has to
# materialise one series per service principal before the outer count() can
# reduce it, and a directory of any size has thousands. The limit is
# max_query_series, 500 by default and not raisable on Grafana Cloud.
#
# The other count(sum by (...)) panels here survive because what they count is
# bounded by definition: domain controllers, or the accounts still on RC4,
# which is the worklist and therefore small by the time anybody looks.
#
# Replaced with ingest volume, which is one series, always, and is a more
# useful thing to have on a collection-health row anyway. RC4 remediation runs
# for months and somebody eventually asks what it costs.
P.append(stat(403, "Telemetry Ingested",
    "Bytes of Kerberos event data ingested in range. Watch this before widening the collection: the Security channel on a busy domain controller is measured in gigabytes a day, which is why the collector drops the rendered message.",
    'sum(bytes_over_time(' + SEL + ' [$__range]))',
    12, 61, 6, 4, NEUT, unit="bytes", no_value="0"))
P.append(stat(404, "Pre-Auth Failures (4771)",
    "Kerberos pre-authentication failures. Not RC4-specific, but a spike here right after an enforcement change is the first symptom.",
    'sum(count_over_time(' + SEL71 + ' [$__range]))',
    18, 61, 6, 4, NEUT, unit="short", no_value="0"))

P.append(table(405, "DC Encryption Posture - DCSupportedEncryptionTypes",
    "What each domain controller reports as its own supported encryption types, read straight from the ticket events. "
    "Anything containing RC4 or DES is a DC still advertising the weak ciphers.",
    'sum by (computer, dc_set) (count_over_time(' + q(SEL, "DCSupportedEncryptionTypes", ["dc_set"], ' | dc_set!="" | dc_set!="-"') + ' [$__range]))',
    0, 65, 14, 8,
    rename={"computer": "Domain Controller", "dc_set": "DCSupportedEncryptionTypes", "Value": "Events"},
    overrides=[{"matcher": {"id": "byName", "options": "DCSupportedEncryptionTypes"},
                "properties": [{"id": "custom.cellOptions", "value": {"type": "color-text"}},
                               {"id": "mappings", "value": [
                                   {"type": "regex", "options": {"pattern": ".*(RC4|DES).*",
                                    "result": {"color": "red", "index": 0}}},
                                   {"type": "regex", "options": {"pattern": "0x18.*",
                                    "result": {"color": "green", "index": 1}}}]}]}],
    sort="Events"))
P.append(ts(406, "Pre-Auth Failures by Domain Controller",
    "Event 4771 over time, per DC. Watch this during and after any encryption-type enforcement change.",
    [tgt('sum by (computer) (count_over_time(' + SEL71 + ' [$__interval]))', "A", legend="{{computer}}")],
    14, 65, 10, 8))

# ---------------- KDC verdict ----------------
# The 4768/4769 events say what happened. These say what the KDC decided
# about it. They only appear once the RC4 disablement phase is active, so
# an empty section here means the phase is off, not that you are clean.
KDC_MAP = [{"type": "value", "options": {
    "201": {"text": "201 warn - client offers only RC4, no explicit config", "color": "orange", "index": 0},
    "202": {"text": "202 warn - service has no AES keys, no explicit config", "color": "orange", "index": 1},
    "203": {"text": "203 BLOCK - RC4-only client refused",                   "color": "red",    "index": 2},
    "204": {"text": "204 BLOCK - service without AES keys refused",          "color": "red",    "index": 3},
    "205": {"text": "205 warn - RC4 explicitly enabled in DDSET policy",     "color": "yellow", "index": 4},
    "206": {"text": "206 warn - client offers only RC4, AES-only config",    "color": "orange", "index": 5},
    "207": {"text": "207 warn - service has no AES keys, AES-only config",   "color": "orange", "index": 6},
    "208": {"text": "208 BLOCK - RC4-only client refused, AES-only config",  "color": "red",    "index": 7},
    "209": {"text": "209 BLOCK - no AES keys refused, AES-only config",      "color": "red",    "index": 8}}}]

P.append(row(1005, "\U0001F6A6 KDC Verdict - Kdcsvc 201-209", 73))
P.append(stat(601, "Requests Blocked by the KDC",
    "Events 203 / 204 / 208 / 209. The KDC refused to issue a ticket because of the RC4 policy. "
    "Every one of these is an authentication that failed, so this is the number that wakes people up.",
    'sum(count_over_time(' + KDC_BLOCK + ' [$__range]))',
    0, 74, 6, 4, RED0, no_value=NODATA, color_mode="value"))
P.append(stat(602, "RC4 Dependencies Warned",
    "Events 201 / 202 / 206 / 207. The KDC still issued the ticket, but flagged the request as depending on RC4. "
    "This is your remediation backlog while the phase is still audit.",
    'sum(count_over_time(' + KDC_WARN + ' [$__range]))',
    6, 74, 6, 4, ORNG0, no_value=NODATA, color_mode="value"))
P.append(stat(603, "DCs Reporting the Policy",
    "Domain controllers that emitted any 201-209 event in range. If this is lower than your DC count, the rest are "
    "either not collected or not running the disablement phase, and their silence means nothing.",
    'count(sum by (computer) (count_over_time(' + SELKDC + ' [$__range])))',
    12, 74, 6, 4, NEUT, no_value="0"))
P.append(stat(604, "Explicit RC4 in DDSET (205)",
    "Event 205, logged when the KDC service starts and finds RC4 explicitly enabled in "
    "DefaultDomainSupportedEncTypes. A configuration finding rather than a live failure, and it survives reboots "
    "until somebody changes the value.",
    'sum(count_over_time(' + '{job="$job", computer=~"$dc", channel="System", event_id="205"}' + ' [$__range]))',
    18, 74, 6, 4, ORNG0, no_value=NODATA, color_mode="value"))

P.append(ts(605, "KDC Events by ID",
    "Warnings and blocks over time. During a migration the shape you want is the warning bands falling to zero "
    "before you move the phase to enforcement, and the block bands never appearing at all.",
    [tgt('sum by (event_id) (count_over_time(' + SELKDC + ' [$__interval]))', "A", legend="{{event_id}}")],
    0, 78, 12, 8))

P.append(table(606, "KDC Verdict by Event and Domain Controller",
    "What each domain controller is reporting, decoded. Blocks in red are already failing. Warnings in orange are "
    "what will fail when the phase moves to enforcement.",
    'sum by (event_id, computer) (count_over_time(' + SELKDC + ' [$__range]))',
    12, 78, 12, 8,
    rename={"event_id": "Event", "computer": "Domain Controller", "Value": "Count"},
    overrides=[{"matcher": {"id": "byName", "options": "Event"},
                "properties": [{"id": "custom.cellOptions", "value": {"type": "color-text"}},
                               {"id": "mappings", "value": KDC_MAP}]}],
    sort="Count"))

# ---------------- raw ----------------
P.append(row(1006, "\U0001F50D Raw Events", 86))
P.append(logs(501, "Raw RC4 Ticket Events",
    "The underlying events behind every number above, reduced to the event_data payload. Use this to confirm a finding "
    "before you touch an account.",
    q(SEL, "TicketEncryptionType", ["etype"], RC4),
    0, 87, 24, 10))
P.append(logs(502, "Raw KDC Events",
    "The Kdcsvc events with their rendered message, which is where the account and service names live. Empty here "
    "means the disablement phase is not emitting, so check RC4DefaultDisablementPhase before you conclude anything.",
    SELKDC,
    0, 97, 24, 10))

DASH = {
  # No __inputs block. DS_LOKI is a real datasource variable (see templating
  # below), so the datasource is switchable from the dashboard itself rather
  # than fixed once at import time. Declaring both would make Grafana prompt
  # for an input and then ignore it.
  "__requires": [
      {"type": "grafana", "id": "grafana", "name": "Grafana", "version": "11.0.0"},
      {"type": "datasource", "id": "loki", "name": "Loki", "version": "1.0.0"},
      {"type": "panel", "id": "stat", "name": "Stat", "version": ""},
      {"type": "panel", "id": "timeseries", "name": "Time series", "version": ""},
      {"type": "panel", "id": "table", "name": "Table", "version": ""},
      {"type": "panel", "id": "logs", "name": "Logs", "version": ""},
      {"type": "panel", "id": "text", "name": "Text", "version": ""}],
  "annotations": {"list": [{"builtIn": 1, "datasource": {"type": "grafana", "uid": "-- Grafana --"},
      "enable": True, "hide": True, "iconColor": "rgba(0, 211, 255, 1)",
      "name": "Annotations & Alerts", "type": "dashboard"}]},
  "description": ("Continuous Kerberos RC4 exposure tracking for Active Directory, built on Windows Security events "
      "4768 and 4769 plus the Kdcsvc KDC events 201-209 from the System log, collected by Grafana Alloy into Loki. Answers who is still receiving RC4 tickets, which "
      "service accounts hold no AES key material, which clients advertise no AES, which ticket requests already fail "
      "with KDC_ERR_ETYPE_NOTSUPP, and which domain controllers still advertise RC4, and what the KDC itself is "
      "warning about or already refusing - continuously, instead of as a point-in-time PowerShell export. Relevant to the RC4 deprecation tracked as CVE-2026-20833. "
      "Replace the YOUR LOGO placeholder in the header panel to brand it."),
  "editable": True, "fiscalYearStartMonth": 0, "graphTooltip": 1, "id": None, "links": [],
  "liveNow": False, "panels": P, "preload": False, "refresh": "5m", "schemaVersion": 39,
  "tags": ["active-directory", "kerberos", "security", "windows", "alloy", "loki", "rc4"],
  # Both variables are scoped to streams that actually carry Kerberos events.
  # An unscoped label_values(job) offers every job in the datasource, which on
  # Grafana Cloud means things like integrations/oracledb and network/syslog:
  # valid Loki jobs, no Kerberos events, guaranteed empty dashboard. Same for
  # the computer list, which otherwise offers every Windows host rather than
  # the handful that are domain controllers.
  "templating": {"list": [
      {"current": {}, "hide": 0, "includeAll": False, "label": "Loki",
       "multi": False, "name": "DS_LOKI", "options": [], "query": "loki",
       "refresh": 1, "regex": "", "skipUrlSync": False, "type": "datasource"},
      {"current": {}, "datasource": {"type": "loki", "uid": DS},
       "definition": "label_values({event_id=~\"" + KERB_IDS + "\"},job)",
       "hide": 0, "includeAll": False, "label": "Job",
       "multi": False, "name": "job",
       "query": {"label": "job", "refId": "LokiVariableQueryEditor-VariableQuery",
                 "stream": "{event_id=~\"" + KERB_IDS + "\"}", "type": 1},
       "refresh": 1, "regex": "", "skipUrlSync": False, "sort": 1, "type": "query"},
      {"allValue": ".*", "current": {}, "datasource": {"type": "loki", "uid": DS},
       "definition": "label_values({job=\"$job\", event_id=~\"" + KERB_IDS + "\"},computer)",
       "hide": 0, "includeAll": True,
       "label": "Domain Controller", "multi": True, "name": "dc",
       "query": {"label": "computer", "refId": "LokiVariableQueryEditor-VariableQuery",
                 "stream": "{job=\"$job\", event_id=~\"" + KERB_IDS + "\"}", "type": 1},
       "refresh": 2, "regex": "", "skipUrlSync": False, "sort": 1, "type": "query"}]},
  "time": {"from": "now-7d", "to": "now"},
  "timepicker": {"refresh_intervals": ["1m", "5m", "15m", "30m", "1h", "2h", "1d"]},
  "timezone": "browser",
  "title": "Active Directory | Kerberos RC4 Remediation",
  "uid": "kerberos-rc4-remediation", "version": 1, "weekStart": ""}


# ---------------------------------------------------------------------------
# Output.
#
# Two shapes of the same dashboard:
#
#   default        DS_LOKI is a real datasource *variable*, so you can switch
#                  Loki source from the dashboard itself. This is the one you
#                  import into your own Grafana.
#
#   --grafana-com  DS_LOKI moves into an __inputs block instead. The public
#                  grafana.com dashboard library is built around __inputs: it
#                  reads that block to render the "select your datasource"
#                  step on import. A dashboard without it is rejected by the
#                  upload form, silently, which is a fun afternoon.
#
# Declaring both at once does not work. Grafana prompts for the input and then
# ignores it, because the variable wins.
# ---------------------------------------------------------------------------
def for_grafana_com(dash):
    d = copy.deepcopy(dash)
    d["__inputs"] = [{
        "name": "DS_LOKI",
        "label": "Loki",
        "description": "Loki datasource holding the Windows events collected by Alloy",
        "type": "datasource",
        "pluginId": "loki",
        "pluginName": "Loki",
    }]
    d["templating"]["list"] = [
        v for v in d["templating"]["list"] if v.get("name") != "DS_LOKI"
    ]
    d["id"] = None
    return d


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--grafana-com", action="store_true",
                    help="emit the __inputs variant accepted by grafana.com")
    ap.add_argument("-o", "--out", help="output path (default: alongside this script)")
    args = ap.parse_args()

    dash = for_grafana_com(DASH) if args.grafana_com else DASH
    default = "dashboard.grafana-com.json" if args.grafana_com else "dashboard.json"
    out = pathlib.Path(args.out) if args.out else pathlib.Path(__file__).resolve().parent / default
    out.write_text(json.dumps(dash, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print("written:", out, "| panels:", len(P))

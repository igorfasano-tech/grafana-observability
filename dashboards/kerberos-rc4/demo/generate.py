#!/usr/bin/env python3
"""
Synthetic Kerberos telemetry for the RC4 Remediation dashboard.

Produces the same shape of log line that Grafana Alloy writes when it
collects Windows Security events 4768/4769/4771 and the Kdcsvc events
201-209 from the System log, and pushes it into a local Loki.

Everything in here is invented. The accounts, the services, the domain
controllers and the IP addresses are all fictional, and the numbers are
tuned so the dashboard has something interesting to show rather than to
represent any real estate.

The story it tells: a domain part-way through RC4 remediation. AES is
winning, a handful of service accounts still have no AES key material,
one domain controller still advertises RC4, and a few requests are
already failing outright.

No third-party packages. Standard library only.

    python3 generate.py
    python3 generate.py --days 14 --url http://localhost:3100
"""
import argparse
import gzip
import json
import random
import time
import urllib.request
from datetime import datetime, timedelta, timezone

random.seed(20260831)  # same dashboard every run, so screenshots are stable

# --- the fictional estate ---------------------------------------------------

DCS = [
    # name,                   advertised encryption set,           weight
    ("DC01.corp.example", "AES256-CTS-HMAC-SHA1-96 AES128-CTS-HMAC-SHA1-96", 34),
    ("DC02.corp.example", "AES256-CTS-HMAC-SHA1-96 AES128-CTS-HMAC-SHA1-96", 31),
    ("DC03.corp.example", "AES256-CTS-HMAC-SHA1-96 AES128-CTS-HMAC-SHA1-96", 26),
    # The one that has not been done yet. This is what the "DCs Advertising
    # RC4" panel is looking for.
    ("DC04.corp.example", "RC4-HMAC AES256-CTS-HMAC-SHA1-96 AES128-CTS-HMAC-SHA1-96", 9),
]

AES_KEYS = "AES256-CTS-HMAC-SHA1-96 AES128-CTS-HMAC-SHA1-96"
AES_SET = "AES256-CTS-HMAC-SHA1-96 AES128-CTS-HMAC-SHA1-96"
RC4_ONLY = "RC4-HMAC"
LEGACY_KEYS = "DES-CBC-MD5 RC4-HMAC"

# Service accounts whose password predates the AES upgrade. They hold no AES
# key material at all, so the fix is a password reset and nothing else.
NO_AES_SERVICES = [
    "MSSQLSvc/sql-legacy01.corp.example:1433",
    "HTTP/intranet-classic.corp.example",
    "CIFS/fileserver-arch01.corp.example",
    "MSSQLSvc/reporting-db.corp.example:1433",
    "HOST/printsrv-old.corp.example",
]

# Services that can do AES perfectly well. The clients asking for RC4 are the
# problem, so the fix lives on the client side.
RC4_CLIENT_SERVICES = [
    "CIFS/fileserver01.corp.example",
    "HTTP/apps.corp.example",
    "LDAP/DC02.corp.example",
    "TERMSRV/jump01.corp.example",
]

HEALTHY_SERVICES = [
    "krbtgt/CORP.EXAMPLE",
    "CIFS/fileserver01.corp.example",
    "HTTP/apps.corp.example",
    "HTTP/portal.corp.example",
    "LDAP/DC01.corp.example",
    "LDAP/DC02.corp.example",
    "MSSQLSvc/sql01.corp.example:1433",
    "MSSQLSvc/sql02.corp.example:1433",
    "TERMSRV/jump01.corp.example",
    "HOST/build01.corp.example",
]

USERS = [
    "a.silva", "m.chen", "j.okafor", "p.novak", "l.dubois", "r.haddad",
    "s.tanaka", "k.oconnor", "d.mueller", "n.varga", "t.eriksen", "b.rossi",
]

SERVICE_ACCOUNTS = [
    "svc_backup", "svc_sqlagent", "svc_reporting", "svc_printspool",
    "svc_archive", "svc_monitoring", "svc_scanner",
]

# Accounts still on RC4. Deliberately a small, named set: this is the worklist
# somebody is meant to work through, not a crowd.
RC4_ACCOUNTS = [
    "svc_backup", "svc_reporting", "svc_printspool", "svc_archive",
    "svc_scanner", "b.rossi", "t.eriksen",
]

SUBNETS = ["10.42.7.", "10.42.19.", "10.61.4.", "172.20.11."]


def ip():
    return random.choice(SUBNETS) + str(random.randint(11, 240))


def pick_dc():
    names = [d[0] for d in DCS]
    weights = [d[2] for d in DCS]
    return random.choices(names, weights=weights)[0]


DC_SET = {name: adv for name, adv, _ in DCS}

# --- event construction -----------------------------------------------------


def event_data(fields):
    """The event_data blob exactly as it arrives from the Windows event XML."""
    return "".join(
        "<Data Name='%s'>%s</Data>" % (k, v) for k, v in fields.items()
    )


def ticket_line(ts, dc, event_id, account, service, etype, status="0x0",
                svc_keys=AES_KEYS, svc_set=AES_SET, client_adv=None):
    if client_adv is None:
        client_adv = AES_SET + " RC4-HMAC"
    payload = {
        "event_id": str(event_id),
        "computer": dc,
        "channel": "Security",
        "timeCreated": ts.strftime("%Y-%m-%dT%H:%M:%S.%f0Z"),
        "level": "Information",
        "event_data": event_data({
            "TargetUserName": account,
            "TargetDomainName": "CORP.EXAMPLE",
            "ServiceName": service,
            "TicketEncryptionType": etype,
            "Status": status,
            "IpAddress": ip(),
            "IpPort": str(random.randint(30000, 62000)),
            "PreAuthType": "2",
            "ServiceAvailableKeys": svc_keys,
            "ServiceSupportedEncryptionTypes": svc_set,
            "ClientAdvertizedEncryptionTypes": client_adv,
            "DCSupportedEncryptionTypes": DC_SET[dc],
        }),
    }
    return ts, json.dumps(payload), {
        "job": "windows_kerberos", "computer": dc,
        "event_id": str(event_id), "channel": "Security",
    }


def preauth_failure(ts, dc, account):
    payload = {
        "event_id": "4771",
        "computer": dc,
        "channel": "Security",
        "timeCreated": ts.strftime("%Y-%m-%dT%H:%M:%S.%f0Z"),
        "level": "Information",
        "event_data": event_data({
            "TargetUserName": account,
            "ServiceName": "krbtgt/CORP.EXAMPLE",
            "TicketEncryptionType": "0xffffffff",
            "Status": "0x18",
            "IpAddress": ip(),
            "PreAuthType": "0",
        }),
    }
    return ts, json.dumps(payload), {
        "job": "windows_kerberos", "computer": dc,
        "event_id": "4771", "channel": "Security",
    }


KDC_MESSAGES = {
    201: "The Key Distribution Center (KDC) encountered a ticket that it was able to issue, but which it will refuse once RC4 is disabled. Account: {acct}. Service: {svc}.",
    202: "The Key Distribution Center (KDC) issued a service ticket using RC4 because the target account does not have AES keys. Account: {acct}. Service: {svc}.",
    203: "The Key Distribution Center (KDC) refused a ticket request because the encryption type is not supported. Account: {acct}. Service: {svc}.",
    204: "The Key Distribution Center (KDC) refused to issue a ticket because the requested encryption type has been disabled. Account: {acct}. Service: {svc}.",
    205: "The Key Distribution Center (KDC) found RC4 explicitly configured in the msDS-SupportedEncryptionTypes of one or more accounts. Review the configuration before disabling RC4.",
    206: "The Key Distribution Center (KDC) identified an account that has no AES key material and will fail once RC4 is disabled. Account: {acct}.",
    207: "The Key Distribution Center (KDC) identified a trust relationship that does not support AES. Trust: CORP.EXAMPLE -> LEGACY.EXAMPLE.",
    208: "The Key Distribution Center (KDC) refused a cross-realm referral because the trust does not support AES. Trust: CORP.EXAMPLE -> LEGACY.EXAMPLE.",
    209: "The Key Distribution Center (KDC) refused a request that relied on a trust configured for RC4 only. Trust: CORP.EXAMPLE -> LEGACY.EXAMPLE.",
}


def kdc_line(ts, dc, event_id):
    msg = KDC_MESSAGES[event_id].format(
        acct=random.choice(RC4_ACCOUNTS),
        svc=random.choice(NO_AES_SERVICES),
    )
    payload = {
        "event_id": str(event_id),
        "computer": dc,
        "channel": "System",
        "source": "Kdcsvc",
        "timeCreated": ts.strftime("%Y-%m-%dT%H:%M:%S.%f0Z"),
        "level": "Warning" if event_id in (201, 202, 205, 206, 207) else "Error",
        "message": msg,
        "event_data": event_data({"AccountName": random.choice(RC4_ACCOUNTS)}),
    }
    return ts, json.dumps(payload), {
        "job": "windows_kerberos", "computer": dc,
        "event_id": str(event_id), "channel": "System",
    }


# --- the shape of a week ----------------------------------------------------


def business_weight(ts):
    """Weekday working hours are busy, nights and weekends are not."""
    if ts.weekday() >= 5:
        return 0.25
    h = ts.hour
    if 8 <= h < 19:
        return 1.0
    if 6 <= h < 8 or 19 <= h < 22:
        return 0.5
    return 0.15


def generate(days):
    now = datetime.now(timezone.utc).replace(minute=0, second=0, microsecond=0)
    start = now - timedelta(days=days)
    entries = []

    total_minutes = days * 24 * 60
    for minute in range(0, total_minutes, 2):
        ts = start + timedelta(minutes=minute)
        w = business_weight(ts)
        progress = minute / total_minutes  # 0.0 at the start, 1.0 now

        # Healthy AES traffic, the overwhelming majority.
        for _ in range(int(random.gauss(9, 3) * w)):
            dc = pick_dc()
            entries.append(ticket_line(
                ts + timedelta(seconds=random.randint(0, 119)),
                dc,
                random.choice([4768, 4769, 4769, 4769]),
                random.choice(USERS + SERVICE_ACCOUNTS),
                random.choice(HEALTHY_SERVICES),
                random.choice(["0x12", "0x12", "0x12", "0x11"]),
            ))

        # RC4 tickets, declining over the window. This is the line the whole
        # dashboard exists to watch go to zero.
        rc4_rate = (1.0 - progress * 0.62) * w * 0.9
        for _ in range(int(random.gauss(rc4_rate, 0.5))):
            dc = pick_dc()
            svc = random.choice(NO_AES_SERVICES + RC4_CLIENT_SERVICES)
            no_aes = svc in NO_AES_SERVICES
            entries.append(ticket_line(
                ts + timedelta(seconds=random.randint(0, 119)),
                dc, 4769,
                random.choice(RC4_ACCOUNTS),
                svc,
                random.choice(["0x17", "0x17", "0x17", "0x18"]),
                svc_keys=LEGACY_KEYS if no_aes else AES_KEYS,
                svc_set=RC4_ONLY if no_aes else AES_SET,
                client_adv=RC4_ONLY if not no_aes else AES_SET + " RC4-HMAC",
            ))

        # Requests already failing with KDC_ERR_ETYPE_NOTSUPP. Rising, because
        # the enforcement is being rolled out DC by DC.
        if random.random() < 0.05 * w * (0.3 + progress):
            entries.append(ticket_line(
                ts + timedelta(seconds=random.randint(0, 119)),
                pick_dc(), 4769,
                random.choice(RC4_ACCOUNTS),
                random.choice(NO_AES_SERVICES),
                "0xffffffff", status="0xe",
                svc_keys=LEGACY_KEYS, svc_set=RC4_ONLY,
            ))

        # Ordinary pre-auth failures. Somebody always mistypes a password.
        if random.random() < 0.06 * w:
            entries.append(preauth_failure(
                ts + timedelta(seconds=random.randint(0, 119)),
                pick_dc(), random.choice(USERS)))

    # KDC audit events. Rare by nature: a handful a day, plus one 205 per DC
    # per boot. Rare is exactly why the dashboard defaults to a 7 day window.
    for day in range(days):
        day_start = start + timedelta(days=day)
        for dc, _, _ in DCS:
            entries.append(kdc_line(
                day_start + timedelta(hours=3, minutes=random.randint(0, 40)),
                dc, 205))
        for _ in range(random.randint(4, 11)):
            entries.append(kdc_line(
                day_start + timedelta(hours=random.randint(7, 20),
                                      minutes=random.randint(0, 59)),
                pick_dc(),
                random.choice([201, 201, 202, 202, 206, 206, 207, 203, 204, 208, 209])))

    return entries


# --- pushing ----------------------------------------------------------------


def push(entries, url):
    """Group by label set, sort by time, send in batches."""
    streams = {}
    for ts, line, labels in entries:
        key = tuple(sorted(labels.items()))
        streams.setdefault(key, []).append((ts, line))

    payload_streams = []
    for key, values in streams.items():
        values.sort(key=lambda v: v[0])
        payload_streams.append({
            "stream": dict(key),
            "values": [[str(int(ts.timestamp() * 1e9)), line] for ts, line in values],
        })

    sent = 0
    batch = []
    batch_lines = 0
    for s in payload_streams:
        for chunk_start in range(0, len(s["values"]), 4000):
            batch.append({
                "stream": s["stream"],
                "values": s["values"][chunk_start:chunk_start + 4000],
            })
            batch_lines += len(batch[-1]["values"])
            if batch_lines >= 8000:
                sent += send(batch, url)
                batch, batch_lines = [], 0
    if batch:
        sent += send(batch, url)
    return sent


def send(streams, url):
    body = gzip.compress(json.dumps({"streams": streams}).encode())
    req = urllib.request.Request(
        url.rstrip("/") + "/loki/api/v1/push",
        data=body,
        headers={"Content-Type": "application/json", "Content-Encoding": "gzip"},
        method="POST",
    )
    for attempt in range(5):
        try:
            with urllib.request.urlopen(req, timeout=30) as r:
                r.read()
            return sum(len(s["values"]) for s in streams)
        except Exception as exc:  # noqa: BLE001
            if attempt == 4:
                raise
            print("  retry %d after %s" % (attempt + 1, exc))
            time.sleep(2 * (attempt + 1))
    return 0


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--url", default="http://localhost:3100",
                    help="Loki base URL (default: http://localhost:3100)")
    ap.add_argument("--days", type=int, default=7,
                    help="how much history to generate (default: 7)")
    args = ap.parse_args()

    print("generating %d days of events..." % args.days)
    entries = generate(args.days)
    print("  %d events across %d domain controllers" % (len(entries), len(DCS)))

    print("waiting for Loki at %s" % args.url)
    for attempt in range(30):
        try:
            urllib.request.urlopen(args.url + "/ready", timeout=3).read()
            break
        except Exception:  # noqa: BLE001
            time.sleep(2)
    else:
        print("Loki did not come up. Is docker compose running?")
        raise SystemExit(1)

    print("pushing...")
    sent = push(entries, args.url)
    print("done: %d lines" % sent)
    print()
    print("Open http://localhost:3000 and pick the Kerberos RC4 dashboard.")
    print("Set the time range to Last 7 days.")


if __name__ == "__main__":
    main()

# Turning on the events

Two different mechanisms, and only one of them is an audit policy. That
distinction is where most of the confusion comes from.

## Security 4768, 4769 and 4771

These are ordinary audit events, controlled by **Audit Kerberos Authentication
Service** and **Audit Kerberos Service Ticket Operations**.

Both are enabled by default on a domain controller under the Default Domain
Controllers Policy, so there is usually nothing to do. Confirm rather than
assume:

```powershell
auditpol /get /subcategory:"Kerberos Authentication Service","Kerberos Service Ticket Operations"
```

Expect `Success and Failure` on both. `Failure` is what carries 4771 and the
`KDC_ERR_ETYPE_NOTSUPP` results, which is the panel that tells you something is
already broken today rather than about to break later.

To set them explicitly, in the Default Domain Controllers Policy:

```
Computer Configuration
  Policies
    Windows Settings
      Security Settings
        Advanced Audit Policy Configuration
          Audit Policies
            Account Logon
              Audit Kerberos Authentication Service        Success, Failure
              Audit Kerberos Service Ticket Operations     Success, Failure
```

### One thing worth knowing about volume

4769 fires on every service ticket request. On a busy domain controller that is
a lot of events, and it is the reason the Alloy config sets
`exclude_event_message = true` on this stream. The rendered English message is a
restatement of `event_data`, which is where the dashboard reads every field
from, so dropping it costs nothing and roughly halves the bytes.

## System 201 to 209, from the KDC

These are **not** an audit policy. There is no subcategory to enable, no channel
to switch on, and no registry value that turns them on directly. Searching for
one is a dead end.

The KDC emits them when the RC4 disablement work is active on that domain
controller. They are the KDC's own verdict:

| Event | Meaning |
|---|---|
| 201, 202 | The KDC issued a ticket it will refuse once the next phase lands |
| 203, 204 | The KDC **refused** a request because of encryption type |
| 205 | A start-up configuration finding, emitted once per boot, not per request |
| 206, 207 | Warnings about accounts or trusts that are not ready |
| 208, 209 | Refusals related to trusts and referrals |

Note 205. It is a configuration finding at start-up rather than a per-request
warning, which is why it gets its own panel on the dashboard instead of being
counted in the warnings total. Counting it with the rest double-counts it and
makes a single reboot look like a spike.

### Whether your KDC is emitting them at all

The behaviour is governed by the RC4 disablement phase:

```powershell
Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\Kdc' -Name RC4DefaultDisablementPhase -ErrorAction SilentlyContinue
```

If the value is absent or `0`, the KDC is in its original behaviour and these
events are not being produced. That is a legitimate state, and the dashboard
shows the KDC row as `not reporting` rather than as a green all-clear, because
those are not the same thing.

Consult Microsoft's current guidance before changing that value. It changes
whether the KDC issues RC4 tickets, so it is a behaviour change on
authentication and not a logging setting, whatever it looks like from here.

### Reading the raw events

```powershell
Get-WinEvent -FilterHashtable @{
    LogName = 'System'
    Id      = 201,202,203,204,205,206,207,208,209
} -MaxEvents 20 | Format-List TimeCreated, Id, ProviderName, Message
```

Check `ProviderName` in the output. It should be `Kdcsvc`. Some builds carry the
longer ETW provider name instead, which is why the Alloy config matches both. A
filter on one spelling alone returns nothing and looks identical to having no
findings.

# Runbook: WireGuard handshake from a never-seen address

Practice runbook for synthetic data. Rule: `rules/wireguard_new_address.yml`. Severity: medium.
The alert catalog (`alert-catalog.md`) says who is told and how fast.

## What it means

A tunnel peer finished a WireGuard handshake from a source address that this peer's key
has never used before. Most of the time the person is simply on a new network. Sometimes
it means the key was copied and someone else is using it.

## Triage steps

1. Write down the peer name, the key fingerprint, the source address, the port and the time (UTC) from the alert.
2. Check whether the person was expected to connect then: working hours, travel, a new home network.
3. Look at the address: has this person used addresses in the same range before? Is it a known provider for them?
4. Search the same hour for other events from that address (failed sign-ins, scans, other peers).
5. Check whether the same key is connected from two different addresses at the same time.
6. Ask the person through a channel you already know is theirs (not by replying to the alert) whether it was them.
7. Record each step and its result, with times, in the case notes.

## Evidence to save

- The alert itself, with its time in UTC.
- The handshake log lines for this peer from one hour before to one hour after the alert (a copy, not the original log).
- The answer from the person, with who asked, how, and when.
- For each saved file: where it came from, the time, who collected it, its SHA-256 fingerprint, and where the original stays.

## When to escalate

- The person says it was not them, or you cannot reach them within one hour.
- The same key is active from two addresses at the same time.
- The address also appears in other alerts.
- Escalate to the person who makes containment decisions, with the evidence above. Do not change the peer's configuration yourself.

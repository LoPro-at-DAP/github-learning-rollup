# Runbook: Repeated failed security-key checks

Practice runbook for synthetic data. Rule: `rules/securitykey_repeated_failures.yml`. Severity: high.
The alert fires when the threshold in `alert-catalog.md` is reached for one user.

## What it means

Someone passed the password step but then failed the security-key step several times in a
short time. Often the person touched the wrong key or the browser had a problem. It can also
mean someone has the password and is trying to get past the second factor.

## Triage steps

1. Write down the user, the key label, the source address, and the time of the first and last failure (UTC).
2. Count the failures in the window and compare with the threshold in the alert catalog.
3. Check whether any success followed the failures, and from which address.
4. Check whether the source address is one this user normally signs in from.
5. Ask the user through a channel you already know is theirs whether they were signing in.
6. If they were not, treat the password as known to someone else.
7. Record each step and its result, with times, in the case notes.

## Evidence to save

- The alert and the matching sign-in events (a copy, not the original log), with times in UTC.
- The user's answer, with who asked, how, and when.
- For each saved file: where it came from, the time, who collected it, its SHA-256 fingerprint, and where the original stays.

## When to escalate

- The user was not signing in, or cannot be reached within 30 minutes.
- A success follows the failures from an address the user does not recognize.
- The same address shows failures for more than one user.
- Escalate to the person who makes containment decisions. The usual next step for a known password is a reset; do not do it yourself unless that is your role.

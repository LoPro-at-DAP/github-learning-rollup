# GitHub learning roll-up

A public record of what I practiced with Git and GitHub, using made-up data only.

> This is the starting skeleton. The class page's roll-up builder generates the full version
> of this file from the steps you completed; paste it over this one through a pull request.

## About this repository

- Every file here is my own writing, a template, or synthetic sample data.
- Nothing here comes from an employer, a client, a real system, or an exam.
- Every change to `main` goes through a pull request, two checks (`validate-rules`,
  `rule-tests`) and a review by someone other than me.

## What I practiced

| Topic | What I did | Evidence |
|---|---|---|
| <topic> | <one sentence> | <link to a commit, pull request, run or tag> |

## Controls I tested

See [AUDIT-REPORT.md](AUDIT-REPORT.md): each control, how I tested it, the artifact, and the result or gap.

## Log of actions

See [ACTIONS-LOG.md](ACTIONS-LOG.md).

## Samples

[`samples/`](samples/) holds synthetic Sigma rules (illustrative, with made-up field names),
their runbooks, tests, sample events and change records. The checks in
`.github/workflows/rollup-checks.yml` run against them on every pull request.

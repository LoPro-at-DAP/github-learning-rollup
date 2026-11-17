# Actions log

One row per action that changed a setting, a repository or an access grant. Dates in UTC.
Link to the evidence (a commit, pull request, check run, tag or settings page) instead of
pasting screenshots. Never record secrets, tokens or recovery codes here.

By the end of the practice this log should hold a row for each of these. Back-fill the earlier
ones with the date you did them; row 1 of the audit report's coverage table points here.

- Turned on two-factor sign-in for my account (recovery codes stored offline)
- Created each repository: `git-practice`, `detection-lab`, `evidence-lab`, `github-learning-rollup`
- Invited Logan as a collaborator
- Created the ruleset on the default branch of `github-learning-rollup`
- Tried a direct push to `main` (refused as expected)
- Turned on GPG verification for codespaces
- Turned on vigilant mode
- Added "Require signed commits" to the ruleset

| Date (UTC) | Repository | What I did | Why | Evidence | Result |
|---|---|---|---|---|---|
| YYYY-MM-DD | <repo> | <for example: created a ruleset on the default branch> | <reason> | <link> | <worked / refused as expected / gap> |

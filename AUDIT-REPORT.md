# Audit report: my practice repositories

**Auditor:** <your name>

**Period covered:** <from> to <to>

**Scope:** my personal GitHub account and the repositories `git-practice`, `detection-lab`,
`evidence-lab` (private) and `github-learning-rollup` (public). Synthetic data only.

**Method:** for each control I check the design (is it configured?) and the operating
effectiveness (does it actually stop or record what it should?). Every row has an artifact
or the word "gap".

## Coverage table

| # | Control | Test (how I checked) | Artifact | Result or gap |
|---|---|---|---|---|
| 1 | Two-factor sign-in on my account (NIST SP 800-53 IA-2(1)) | Settings → Password and authentication shows two-factor authentication on; recovery codes stored offline | ACTIONS-LOG entry with the date checked | <pass / fail / gap> |
| 2 | No direct pushes to `main` on `github-learning-rollup` (CM-5) | Design: the ruleset targets the default branch and is Active. Operating: a direct push to `main` was refused | Link to the ruleset; ACTIONS-LOG entry quoting the refusal | <result> |
| 3 | A second person approves every change (AC-5, SOC 2 CC8.1) | Pull requests merged only after an approval from someone other than the author | Link to a merged pull request showing the approval | <result> |
| 4 | Required checks gate the merge (`validate-rules`, `rule-tests`) | A pull request with a broken rule could not be merged until fixed | Link to the failing and the passing check runs | <result> |
| 5 | Force pushes and deletion of `main` are blocked | Ruleset settings show both restrictions | Link to the ruleset | <result> |
| 6 | Commits are signed and verified (AU-10) | Commits on `main` show "Verified"; the ruleset requires signed commits | Link to the commit list; output of a verification query | <result> |
| 7 | Secret check catches a test secret before merge | A fake key added on a branch made the secret check fail; it was removed before the merge | Link to the failing run in `detection-lab` | <result> |
| 8 | Evidence files are fingerprinted and still match (SI-7) | `sha256sum -c` on the manifest reports OK for every file | `evidence-lab` manifest and the check output | <result> |
| 9 | A rollback point exists for each release | Annotated tag and release on `github-learning-rollup` | Link to the tag `v1.0` and its release | <result> |
| 10 | Branch rules on my private repositories | GitHub Free does not enforce branch protection or rulesets on private repositories | gap | gap. Compensating control: I use a branch and pull request for every change, the checks run on every pull request, and I review the merge history in this report. The public repository carries the enforced rules. |

## Findings

<one short paragraph per finding: what, where, why it matters, and what I recommend>

## Gaps and compensating controls

<each gap from the table, the risk it leaves, and what reduces that risk>

## Sign-off

<name, date, and the commit ID of this report>

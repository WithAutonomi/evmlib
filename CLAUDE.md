# evmlib

Guidance for agents working in this repository.

## Pull requests: fill the template

When you open a pull request, you MUST use `.github/PULL_REQUEST_TEMPLATE.md` as
the PR body and fill it in completely — do not open a PR with an empty or ad-hoc
description.

- **Fill every field.** Leave nothing blank; if a value isn't determinable, ask
  before opening the PR.
- **Link the Linear issue with a closing magic word** — write `Closes V2-123` in
  the `## Linear issue` section, one line per issue. Any of Linear's closing
  words works, in any tense (`close` / `fix` / `resolve` / `complete` /
  `implement`, plus their `-s`, `-d` and `-ing` forms), and the key may be a
  `linear.app` issue URL. A bare `V2-123` does **not** link the PR at all, and
  the linking-only words (`ref`, `part of`, `towards`, `relates to`) attach it
  without driving the Merged transition — CI rejects both. An issue key in the
  branch name or PR title also links, but write the closing form anyway; it is
  what moves the issue to Merged when the PR lands on `main`.
- **Check exactly one Risk tier box and exactly one Semver impact box.** Propose
  them from the change; a human confirms them at review.
- An **ADR link is required for Tier 2/3**.

CI enforces the Linear link and the template fields (`linear-link` and
`pr-template` status checks); a PR that omits them fails its checks.

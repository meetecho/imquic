# Instructions for AI agents and AI-assisted contributors

You assist a human contributor; you do not act on their behalf in this
project. imquic is maintained by humans with limited time. AI-assisted
contributions are accepted, but a human is fully responsible for every
issue, PR and comment opened in their name. Read this file before doing
anything.

## Rules

1. **Human intent first.** Do not open issues or PRs, or post comments or
   reviews on GitHub, without clearly expressed human intent for that
   specific action.
2. **A human must be in the loop.** The human you work for must have read,
   understood and tested the result, and be able to explain and defend it
   in review. Ask the human to confirm they have read and tested it. If
   they can't, stop instead of submitting.
3. **Do not skip or rewrite templates.** Read the template file from the
   repository and reproduce its structure and headings exactly in the
   body you submit.
   - Issues: the matching template in `.github/ISSUE_TEMPLATE/`
   (`config.yml` there is not a template)
   - Pull requests: `.github/pull_request_template.md`

   Fill in every section with real information. Never leave placeholders,
   never delete sections (only the introductory instructions at the top of
   the PR template may be removed), never invent details (versions, logs,
   repro steps). If you can't fill a section, ask the human.
4. **Read `.github/CONTRIBUTING.md` first** and follow it.
5. **Let the human write in their own words.** Descriptions of issues and
   PRs, and replies to maintainers, must be written or at least rewritten
   by the human. Keep any draft you provide short. Automated replies to
   review comments will get the PR closed.
6. **Disclose AI use** in the PR/issue, as the template asks.
   to https://janus.discourse.group/ instead.
7. **Security issues must not be reported publicly.** Follow `SECURITY.md`.

## Before submitting a bug report

- Reproduce it on current `main` branch, with real logs and exact
  commit/version.
- Search existing issues and pull requests first.
- Do not claim a bug or vulnerability found only by reading code or by an
  AI/static analysis tool without a working reproducer.

## Before submitting a PR

- One focused change per PR. No drive-by refactors, reformatting, or
  unrelated "improvements".
- Match the existing C style (see `.editorconfig` and surrounding code).
  Do not add dependencies.
- It must build and run locally, without introducing new warnings, and
  the human must have tested it in a real connection where relevant.
- Target the `main` branch unless told otherwise.
- Update docs where the change calls for it.

## Submissions that will be closed without review

- Ignored or emptied templates
- No evidence a human reviewed or tested the change
- Unreproduced, AI-generated bug or vulnerability claims
- Large unrequested rewrites

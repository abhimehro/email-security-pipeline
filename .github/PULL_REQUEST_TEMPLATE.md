<!--
  Thank you for contributing to the Email Security Pipeline!
  Please fill in as much of the template as possible. Reviewers use this
  information to understand the purpose and safety of your changes.
-->

## Summary

<!-- A short (1–3 sentence) description of what this PR does and why. -->

Closes #<!-- issue number -->

---

## Type of Change

<!-- Check all that apply. -->

- [ ] `feat` – new feature
- [ ] `fix` – bug fix
- [ ] `docs` – documentation only
- [ ] `chore` – maintenance (deps, config, CI)
- [ ] `test` – test additions or improvements
- [ ] `perf` – performance improvement
- [ ] `refactor` – code restructuring, no behaviour change

---

## What Changed and Why

<!--
  Explain the key decisions you made. Prefer "why" over "what" — the diff
  already shows what changed.
-->

---

## How Was This Tested?

<!--
  Describe the tests you ran, e.g.:
  - "Added unit tests in tests/test_spam_analyzer.py covering X"
  - "Ran python3 -m pytest and all 208 tests pass"
  - "Manually verified against a live Gmail IMAP connection"
-->

- [ ] `python3 -m pytest` passes locally
- [ ] `pre-commit run --all-files` passes locally

---

## Security Implications

<!--
  Does this PR touch authentication, credential handling, input parsing,
  external network calls, or file I/O? Describe any security considerations
  (even if the answer is "none — this is a docs change").

  IMPORTANT: Never include real credentials, tokens, or secrets in this
  description. See CONTRIBUTING.md for the full secrets policy.
-->

- [ ] No secrets or credentials are introduced or exposed by this change
- Security notes: <!-- e.g. "None — documentation change only" -->

---

## Checklist

- [ ] Branch follows naming convention (`feat/`, `fix/`, `docs/`, etc.)
- [ ] Commit messages are clear and descriptive
- [ ] New or modified code includes relevant tests
- [ ] Pre-commit hooks pass (`pre-commit run --all-files`)
- [ ] Documentation updated if behaviour changed (README, docstrings, etc.)
- [ ] No secrets, credentials, or `.env` files are included in this PR

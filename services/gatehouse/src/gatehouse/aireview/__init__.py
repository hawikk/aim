"""AI/LLM security review — the layer that reads the diff like a reviewer
(repo-graph slice).

Static scanners match patterns; they do not reason about whether the account
id on line 4 is ever checked against the caller on line 9. This package sends
the PR's added hunks — plus a capped window of surrounding context, and a
bounded call-graph of caller/callee *signatures* for the symbols the PR
touched — to a configurable, self-hostable LLM endpoint and
normalizes what comes back into ordinary `Finding`s.

Three rules shape everything in here:

* **Advisory by default.** An AI finding never fails a check unless the repo
  opts in with `ai_review.blocking: true`. The model's output is untrusted
  input (the PR author controls the prompt's context), so v1 treats it as a
  second opinion, not a gate.
* **Data minimization.** The bundle is added lines + ±N context lines +
  signature-only call-graph edges, capped per file / per graph slice / in
  total. No whole files, no function bodies from neighbouring files, no
  history, and nothing is persisted — findings and token/cost stats are the
  only artifacts (D4).
* **Soft failure.** A dead endpoint degrades the check to `neutral` with the
  reason on it, exactly like a crashed scanner. It can never turn a run red,
  and it can never turn a run silently green either.
"""

# Landing page

Active site (AI Monitoring only — multi-product stack framing removed):

| File | Role |
|------|------|
| [`index.html`](./index.html) | Hero + product features + pricing |
| [`video.html`](./video.html) | Product video / walkthrough |

Storyboard + capture plan: [`VIDEO.md`](./VIDEO.md).  
Poster until `assets/demo.mp4` ships: [`assets/demo-poster.svg`](./assets/demo-poster.svg).  
The page probes for the MP4 and keeps a designed “coming soon” empty state if missing (no broken player).

Public copy is **exclusively AI Monitoring**: usage visibility, policies, and guardrails for AI coding tools. No CNAPP / CI/CD / multi-product stack language on the live pages.

Pricing numbers come from the pricing decision record. Do not invent alternate public prices.

## Preview

```bash
python3 -m http.server 8000 --directory apps/landing
# open http://127.0.0.1:8000/
# open http://127.0.0.1:8000/video.html
```

## Visual variants

| File | Scroll behavior | Restore |
|------|-----------------|---------|
| `index.html` | Galaxy lives in the hero and scrolls away with it | (current) |
| `variants/fixed-viewport.html` | Galaxy is `position: fixed` on the viewport (v9 black-hole fix) | `cp apps/landing/variants/fixed-viewport.html apps/landing/index.html` |

Git rollback (same tree as fixed variant at tag time):

```bash
git checkout landing-fixed-viewport-v9 -- apps/landing/index.html
# or
git switch landing/fixed-viewport
```

Public marketing host is the GitHub Pages repo `hawikk/getaimonitoring` (`CNAME` `getaimonitoring.com`). This monorepo stays the source of truth; publish the static tree from `apps/landing/` to that repo. Pages serving and the custom domain are configured only on the dedicated marketing repo — never on this one.

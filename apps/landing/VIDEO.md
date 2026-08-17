# Product video

**Current asset:** `apps/landing/assets/demo-remotion.mp4` (16:9, Remotion-based)  
**Social cut:** `apps/landing/assets/demo-remotion-9x16.mp4` (9:16)  
**Poster:** `apps/landing/assets/demo-poster.svg`  
**Page:** [`video.html`](./video.html)  
**Source:** [`remotion/`](./remotion/) — Remotion project with TypeScript compositions

**Privacy rule:** Real dashboard screenshots from `apps/landing/demo.html` (synthetic sample-data.json). No fake UI, no customer data, no PII. HARD FAIL: username "hawikk" is banned from promo frames.

## Structure (23.5s — trailer cut)

| Time | Scene | On-screen |
|------|-------|-----------|
| **0–1.0s** | Opening | AI Monitoring logo reveal |
| **1.0–7.5s** | Activity | Live event trail (table-only crop, full bleed) + row slide-in reveal |
| **7.5–14.0s** | Findings | Critical security findings + sliding highlight emphasis |
| **14.0–20.5s** | Users | User usage table + row stagger reveal |
| **20.5–23.5s** | CTA | "Self-host it." + logo |

**Pacing:** Trailer-style (6.5s max per product screen). Continuous product journey with overlaid copy—no mid-film black title cards.

## Remotion implementation

**Location:** [`remotion/`](./remotion/)

Production-quality Remotion project with TypeScript compositions. Screenshots recaptured from `apps/landing/demo.html` (synthetic 12-seat cohort, NOT personal mode). Uses spring-based animations, smooth easing curves, and modern design aesthetic.

**Tech stack:**
- Remotion 4.x (React-based video rendering)
- TypeScript for type safety
- Spring animations (not linear interpolation)
- Real screenshots from demo.html with modern browser chrome
- System font stacks (Inter/JetBrains Mono with graceful fallbacks)

**Preview and render:**
```bash
cd apps/landing/remotion
npm install
npm start                # Preview in Remotion Studio at http://localhost:3000
npm run build            # Render 16:9 to out/promo-16x9.mp4
npm run build:9x16       # Render 9:16 to out/promo-9x16.mp4
npm run build:all        # Render both formats
```

**Output:**
- `demo-remotion.mp4` — 16:9 hero (1920x1080, 23.5s, ~12 MB, h264)
- `demo-remotion-9x16.mp4` — 9:16 social (1080x1920, 23.5s, ~6 MB, h264)

**Music:**
- Track: "Deep Urban" by Eugenio Mininni
- Source: Mixkit (mixkit.co)
- License: Mixkit Free License
- Duration: 24s (trimmed and faded to match video)

## Screenshot capture process

Screenshots are captured from `apps/landing/demo.html` using Playwright automation:

1. Start local HTTP server: `cd apps/landing && python3 -m http.server 8181`
2. Run capture script: `cd apps/web && node scripts/capture-demo-screenshots.mjs`
3. Verify no "hawikk": script automatically checks and fails if found
4. Screenshots saved to `apps/landing/remotion/public/`

**Captured views:**
- `overview.png` — Main dashboard with KPIs
- `findings.png` — Security findings view
- `activity.png` — Activity trail and audit log
- `guardrails.png` — Guardrails configuration

**Data source:** `demo/sample-data.json` — Synthetic 12-seat cohort (jdoe, rpatel, agarcia, tkim, etc.). Actors are "eng-042", "eng-118", etc. — never real usernames.

## Design notes

- **Aesthetic:** Black background, white type, restrained—inspired by Linear/Vercel launch films
- **Motion:** Spring-based animations (not linear), smooth scale/drift, professional easing
- **Type:** System stacks with proper fallbacks (no external font endpoints)
- **Framing:** Real screenshots with modern browser chrome (10px dots, subtle gradient)
- **Pacing:** Tighter than v1 (2.5s opening, 8.5s walkthroughs, 15s guardrails+privacy, 15s CTA)
- **Silent:** No audio track; designed for sound-off viewing

## Archive

The original Playwright capture (`demo.mp4`, ~1.3 MB) remains as a fallback but is no longer the primary asset. Current Remotion version uses:
- CURRENT main UI (not Aug 8 personal-mode screenshots)
- Synthetic demo data (not real ingest)
- Spring animations (not Ken Burns)
- Modern framing (not raw PNG dumps)

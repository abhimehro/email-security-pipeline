# Stream 2: email-security-pipeline outage — 2026-07-09

## Symptom
LaunchAgent errors; no flagged/suspicious notifications.

## Root causes
1. Colima VM dead since ~2026-06-04; later `colima` CLI missing → start script waited/failed; no docker.sock → no container.
2. Start script historically swallowed `colima start` failures.
3. Alert gating required `overall_threat_score >= THREAT_LOW` (30) while `risk_level` can be medium/high from layer thresholds at much lower scores → silent drop of notifications.
4. After Colima recovery, container still ran a 6-week-old image (src not bind-mounted) so gating fix was not live until rebuild.

## Fix
- Harden `launchd/start-email-security-pipeline.sh` (resolve bins, fail fast, longer wait, no swallowed errors)
- Fix `AlertSystem.send_alert` to notify on medium/high risk OR score ≥ THREAT_LOW
- `scripts/recover-colima-pipeline.sh` for shared-Colima-safe recovery + rebuild + ntfy test
- Rebuild + recreate container; verify IMAP + webhooks + synthetic alert

## Verification (2026-07-09 ~18:47–18:49Z)
- Colima running; container healthy (Created 2026-07-09T18:47:36Z)
- Gating code present in container (`risk not in ("medium", "high") and score_below_floor`)
- IMAP cycle analyzed mail; 25+ webhook successes in rebuild window
- Synthetic: score=5/low → 0 dispatch; score=18/high → webhook OK
- Host ntfy: `Stream2 E2E OK` on topic `email-security-pipeline`
- LaunchAgent last exit 0 (one-shot compose up — expected)

# Lessons

## 2026-07-09 — Colima + Control D host DNS

- **Pattern:** Lima auto-forwards guest `127.0.0.1:53` → host limactl TCP *:53, which blocks Control D (`ctrld`) bind. personal-config repair then fails dig @127.0.0.1.
- **Prevent:** Keep Colima, but ensure `~/.colima/_lima/_config/override.yaml` ignores guest DNS (`~/dev/personal-config/scripts/free-port53-for-controld.sh --patch-colima-ignore`). Never `colima delete` to "fix" DNS — shared with Jellyfin plans.
- **Related:** personal-config Lesson 0dk / 0do.

## 2026-07-09 — Stream 2 email-security-pipeline outage

- **Pattern:** LaunchAgent `compose up -d` can look "healthy" while the *image* is weeks stale — `src/` is COPY'd at build time, not bind-mounted. After code fixes, always `--rebuild`.
- **Pattern:** Alert gating on `overall_threat_score >= THREAT_LOW` alone drops layer-flagged medium/high when sum score stays below the floor (spam high at ~10 vs THREAT_LOW=30).
- **Pattern:** Silent `colima start || true` + long wait = launchd KeepAlive spam; fail fast if colima binary missing; never `colima delete` (shared with Jellyfin).
- **Prevent:** Recovery script includes `--rebuild --test-alert`; start script fails fast without colima; unit test covers medium/high below threat_low.

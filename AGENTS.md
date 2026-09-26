# Monitoring Single-Lane Agent Contract

Mandatory entry: scripts/agent_preflight.sh

Repository: Codestra-Loki
Canonical active worktree: /home/codestra/Worktrees/Monitoring-Active-20260926/Codestra-Loki
Canonical branch: governance/single-active-lane-20260926
Recorded base: main at 44ad933358efdb45182183d2d03313bc4c942fd5

One-line continuation:
cd /home/codestra/Worktrees/Monitoring-Active-20260926/Codestra-Loki && ./scripts/agent_preflight.sh

Rules:
- Work only in the canonical active worktree and active branch above.
- Never edit protected main, detached HEAD, a dirty start, or a branch with the wrong upstream.
- .codestra-mission/ACTIVE-LANE.env is authority; stale base SHA or wrong origin fails closed.
- Preserve old lanes as read-only reconciliation evidence. Never reset, stash, discard, rewrite, force-push, or blindly delete history.
- Never add public /metrics or /internal exposure, wildcard CORS, alternate public monitoring ports, or auth/correlation/audit-header bypasses.
- Never add production-effect commands on this lane. Monitoring work remains read-only/no-effect.
- Before publication run scripts/agent_preflight.sh --certify and perform a fresh remote-head compare-and-swap.

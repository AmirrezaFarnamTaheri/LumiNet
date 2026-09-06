# Post-refactor-233 state machines

Mobile Tor lifecycle models stopped -> starting -> bootstrapping -> ready -> stopping/failed with foreground/background and on-demand residency evidence. Network loss cannot preserve ready evidence. Security posture uses pass/fail/unknown/not-applicable with unknown never promoted to pass. Other 233 planners are stateless deterministic transforms over caller-supplied evidence.

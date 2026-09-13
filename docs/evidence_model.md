# Evidence Model

Every automated check should preserve enough provenance for a reviewer to answer four questions:

1. **What was collected?** Identity, configuration, log, policy, or state evidence.
2. **Where did it come from?** The authoritative source or export mechanism.
3. **When was it collected?** Timestamp and assessment period.
4. **How was it evaluated?** A documented rule with a mapped control objective.

The sample evidence therefore includes an `evidence_id`, `source`, `collected_at`, organizational policy assumptions, and the objects evaluated.

A production implementation would additionally record tenant/subscription scope, collector version, API/query version, hash/checksum, collection status, and reviewer approval.

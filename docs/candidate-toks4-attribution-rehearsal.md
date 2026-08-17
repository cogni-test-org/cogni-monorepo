# Candidate-local toks4 attribution rehearsal

This temporary test fixture keeps the candidate-a attribution path environment-local.
The candidate GitHub App remains installed only on `cogni-test-org`; no production webhook is forwarded or replayed.

For task.5029, the candidate catalog exposes an infra-only resolver row plus an in-repo mirror of toks4's identity profile. That mirror names `cogni-test-org/test-cog` as its source, so a normal test-org pull-request merge can exercise webhook verification, receipt routing, epoch allocation, wallet review, distribution publication, and claim. The row deliberately has no `source_repo`, deploy environments, or node port: it is resolver input, not a deployable node or cross-environment event bridge.

Validation requires candidate logs to show `fallbackToOperator: false` and the toks4 node id on the accepted receipt. Remove the catalog/profile fixture after the distribution rehearsal.

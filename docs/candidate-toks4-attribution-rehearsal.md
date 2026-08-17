# Candidate-local toks4 attribution rehearsal

This temporary test fixture keeps the candidate-a attribution path environment-local.
The candidate GitHub App remains installed only on `cogni-test-org`; no production webhook is forwarded or replayed.

For task.5029, the candidate catalog resolves toks4 through `cogni-test-org/test-cog` so a normal test-org pull-request merge can exercise webhook verification, receipt routing, epoch allocation, wallet review, distribution publication, and claim.

Validation requires candidate logs to show `fallbackToOperator: false` and the toks4 node id on the accepted receipt. Remove the catalog/profile fixture after the distribution rehearsal.

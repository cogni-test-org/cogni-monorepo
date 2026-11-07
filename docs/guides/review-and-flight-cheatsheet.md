# Review and flight cheatsheet

This guide is the reference for shipping a change. Keep it up to date in this repo.

## Steps

1. Open a pull request against `main`.
2. Ask the operator to review it.
3. Flight the head SHA to candidate-a and check `/version`.
4. Validate the candidate, then merge through the operator.
5. Promote to preview, then production.

## Notes

- Copy these steps into each node repo so every team has its own version.
- When the process changes, update this file and the copies in each node repo.

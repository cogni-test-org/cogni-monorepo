#!/usr/bin/env bash
# SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
# SPDX-FileCopyrightText: 2026 Cogni-DAO
# Owned rollback input only. The caller first enumerates the committed real fleet.
# No deployed catalog, routing target, secret, or committed pin is changed.
seed_historical_lane_catalog() {
  local destination="$1" node
  mkdir -p "$destination"
  cp "$CATALOG_DIR"/*.yaml "$destination/"
  for node in poly red toks5; do
    printf '{"name":"%s","type":"node","envs":["candidate-a","preview","production"],"deployment_provider":{"candidate-a":"akash","preview":"akash","production":"akash"}}\n' "$node" > "$destination/$node.yaml"
  done
  export CATALOG_DIR="$destination" COGNI_CATALOG_ROOT="$destination" FLEET_CONTROL_ENV=production
  # Callers must reload image-tags at TOP LEVEL: its declare arrays would be
  # function-local here and disappear before historical identity assertions.
}

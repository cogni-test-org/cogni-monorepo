#!/usr/bin/env bash
# SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
# SPDX-FileCopyrightText: 2026 Cogni-DAO
# Read the real primary node. Never create or restore deployment catalog rows.
catalog_test_primary_node() {
  local catalog_dir="$1" node
  node="$(yq -N 'select(.type == "node" and .is_primary_host == true) | .name' "$catalog_dir"/*.yaml)" || return 1
  if [[ ! "$node" =~ ^[a-z][a-z0-9-]{0,62}$ ]]; then
    echo 'Expected exactly one primary node in the current catalog' >&2
    return 1
  fi
  printf '%s\n' "$node"
}

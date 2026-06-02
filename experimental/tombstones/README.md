# Stigmem Tombstones Plugin

Experimental right-to-be-forgotten tombstones plugin for Stigmem.

This package provides the `stigmem-plugin-tombstones` source package for alpha
validation. It registers through the `stigmem.plugins` entry point group and is
loaded by `stigmem-node` only when explicitly installed and configured by an
operator.

## Status

Tombstones remain experimental. Installing this package does not add tombstone
filtering or propagation to the supported default surface. Default Stigmem
installs keep tombstone behavior disabled unless the plugin is registered and
the operator enables the relevant gates.

The package metadata is publication-shaped for the plugin readiness track, but
registry publication remains on hold until dry-run evidence and maintainer
clearance are recorded. See the feature record under `features/tombstones/` for
the current status, evidence, and security notes.

## Installation

```bash
pip install --pre stigmem-node==0.9.0a8 stigmem-plugin-tombstones==0.1.0
```

## Enable

Set the plugin gate environment variable to opt in:

```bash
export STIGMEM_TOMBSTONES_ENABLED=1
```

The default install is inert; tombstone hook behavior only activates when the
package is installed, discovered through the `stigmem.plugins` entry point, and
the operator enables the gate. Admin and federation route contracts are mounted
but access-gated by default; recall filtering and peer propagation remain
separately gated.

## Disable

Unset the plugin gate environment variable, or set it to any value other than
`1`, `true`, `yes`, or `on`:

```bash
unset STIGMEM_TOMBSTONES_ENABLED
```

The plugin returns to inert state at the next process start. No data migration
is required; core scope, tenant, audit, and federation enforcement continues to
hold.

## Test

From a Stigmem repository checkout with development dependencies installed:

```bash
uv run pytest node/tests/plugins/test_tombstone_plugin_scaffold.py \
  node/tests/plugins/test_tombstone_plugin_gating.py
```

The package itself ships no separate test tree; upstream plugin validation
lives in `node/tests/plugins/`.

## Uninstall

```bash
pip uninstall stigmem-plugin-tombstones
```

Removing the package is sufficient. The gate environment variable becomes moot
once the entry point is no longer discoverable.

## Project Links

- Repository: <https://github.com/eidetic-labs/stigmem>
- Feature record: <https://github.com/eidetic-labs/stigmem/tree/main/features/tombstones>
- Plugin source: <https://github.com/eidetic-labs/stigmem/tree/main/experimental/tombstones>
- Issue tracker: <https://github.com/eidetic-labs/stigmem/issues>

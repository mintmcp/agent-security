# Agent Instructions

This document contains important notes for AI agents working on this codebase.

## Version Synchronization

We now publish two PyPI packages and ship a Claude plugin. When bumping versions for a release, update ALL of the following to the same version string (e.g., "0.1.10"):

1. `.claude-plugin/marketplace.json`
   - Top-level `version`
   - `plugins[0].version` (the `secrets-scanner` plugin)
2. `plugins/secrets_scanner/.claude-plugin/plugin.json`
   - `version`
3. `plugins/secrets_scanner/hooks/secrets_scanner_hook.py`
   - `__version__`
4. `packages/claude-secret-scan/pyproject.toml`
   - `[project].version`
5. `packages/cursor-secret-scan/pyproject.toml`
   - `[project].version` and dependency pin on `claude-secret-scan == X.Y.Z`
6. (Legacy) Root `pyproject.toml` if still used locally
   - `[project].version` (CI no longer builds from root)

### Version Bump Checklist

- [ ] Update `.claude-plugin/marketplace.json` (package + plugin versions)
- [ ] Update `plugins/secrets_scanner/.claude-plugin/plugin.json` (plugin metadata)
- [ ] Update `plugins/secrets_scanner/hooks/secrets_scanner_hook.py` (`__version__`)
- [ ] Update `packages/claude-secret-scan/pyproject.toml`
- [ ] Update `packages/cursor-secret-scan/pyproject.toml` (and pin dependency)
- [ ] Update legacy root `pyproject.toml` if necessary
- [ ] Commit with message: "Bump version to X.Y.Z"
- [ ] Tag release: `git tag vX.Y.Z`

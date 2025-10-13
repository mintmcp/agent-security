# Agent Instructions

This document contains important notes for AI agents working on this codebase.

## Version Synchronization

When bumping the version number for a release, the following files MUST be updated to keep versions in sync:

1. **`.claude-plugin/marketplace.json`** (line 4)
   - Overall package version for the marketplace listing

2. **`.claude-plugin/marketplace.json`** (line 14)
   - Individual `secrets-scanner` plugin version within the plugins array

3. **`pyproject.toml`** (line 7)
   - Python package version for PyPI distribution

4. **`plugins/secrets_scanner/.claude-plugin/plugin.json`** (line 3)
   - Individual plugin metadata version

All four locations should have the same version string (e.g., "0.1.8").

### Version Bump Checklist

- [ ] Update `.claude-plugin/marketplace.json` (package version)
- [ ] Update `.claude-plugin/marketplace.json` (plugin version)
- [ ] Update `pyproject.toml` (project version)
- [ ] Update `plugins/secrets_scanner/.claude-plugin/plugin.json`
- [ ] Commit with message: "Bump version to X.Y.Z"
- [ ] Tag release: `git tag vX.Y.Z`

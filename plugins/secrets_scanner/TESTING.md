# Directory Scanner for Testing & Fine-Tuning

This document describes how to use the `scan_directory.py` script to test the secret scanner and identify false positives/negatives for fine-tuning.

## Quick Start

```bash
# Scan current directory
python3 scan_directory.py .

# Scan a specific directory with progress output
python3 scan_directory.py /path/to/project --verbose

# Scan with additional exclusions
python3 scan_directory.py . --exclude tests --exclude fixtures

# Get JSON output for processing
python3 scan_directory.py . --json > results.json

# Limit number of files (useful for large repos)
python3 scan_directory.py . --max-files 100
```

## Features

### What It Does
- Recursively scans all files in a directory
- Reports which files contain potential secrets
- Shows line numbers and detection types
- **Does NOT expose the actual secret values** (for safety)
- Color-coded output for easy reading
- Skips binary files and common build directories

### Default Exclusions
The scanner automatically skips these directories:
- `.git`, `.svn`, `.hg` (version control)
- `node_modules` (npm)
- `__pycache__`, `.pytest_cache`, `.mypy_cache` (Python)
- `.venv`, `venv` (virtual environments)
- `dist`, `build`, `.egg-info` (build artifacts)
- `.tox` (testing)

## Usage Examples

### Example 1: Scan with Verbose Output
```bash
python3 scan_directory.py ~/my-project --verbose
```

Output shows progress for each file:
```
  CLEAN LICENSE
  FOUND secrets_scanner_hook.py (2 findings)
  CLEAN pyproject.toml
  SKIP node_modules/... (excluded)
```

### Example 2: JSON Output for Analysis
```bash
python3 scan_directory.py . --json | jq '.findings | group_by(.type) | map({type: .[0].type, count: length})'
```

### Example 3: Test on Limited Files
```bash
python3 scan_directory.py /large/repo --max-files 50 --verbose
```

## Output Format

### Human-Readable Report
```
=== Secret Scanner Directory Report ===

Summary:
  Files scanned:      11
  Files skipped:      142
  Files with secrets: 2
  Total findings:     125

Files with Findings:

● /path/to/file.py
  GitHub Personal Access Token: lines 163, 164, 165
  AWS Access Key ID: lines 155, 156, 157
  Stripe Secret Key: lines 179, 180
```

### JSON Format
```json
{
  "files_scanned": 11,
  "files_skipped": 142,
  "files_with_findings": 2,
  "total_findings": 125,
  "findings": [
    {
      "file": "/path/to/file.py",
      "line": 163,
      "type": "GitHub Personal Access Token"
    }
  ],
  "errors": []
}
```

## Fine-Tuning Workflow

### 1. Scan Your Repository
```bash
python3 scan_directory.py /path/to/repo --json > scan_results.json
```

### 2. Review Findings
For each finding, check the file manually:
```bash
# Get unique files with findings
jq -r '.findings[].file' scan_results.json | sort -u

# Get findings for specific file
jq '.findings[] | select(.file == "/path/to/file.py")' scan_results.json
```

### 3. Identify False Positives/Negatives

**False Positives** - The scanner detected something that isn't a real secret:
- Pattern definitions (like in `secrets_scanner_hook.py`)
- Test data (like in `read_hook_test.py`)
- Documentation examples
- Mock/placeholder values

**False Negatives** - The scanner missed real secrets:
- Non-standard formats
- Custom API key patterns
- Organization-specific credential formats

### 4. Update Patterns

Edit `secrets_scanner_hook.py` and modify the `PATTERNS` dictionary:

```python
# To reduce false positives, make regex more specific
"OpenSSH Private Key": re.compile(
    r"-----BEGIN OPENSSH PRIVATE KEY-----[\s\S]+?-----END OPENSSH PRIVATE KEY-----"
),

# To catch new patterns, add new entries
"Custom API Key": re.compile(r"\bcustom_api_[A-Za-z0-9]{40}\b"),
```

### 5. Re-test
```bash
python3 scan_directory.py /path/to/repo --json > scan_results_v2.json

# Compare results
diff <(jq -S . scan_results.json) <(jq -S . scan_results_v2.json)
```

## Command-Line Options

| Option | Description |
|--------|-------------|
| `directory` | Directory to scan (required) |
| `--exclude DIR` | Additional directory/file to exclude (repeatable) |
| `--max-files N` | Limit number of files to scan |
| `--verbose, -v` | Show progress for each file |
| `--json` | Output JSON instead of formatted report |
| `--no-color` | Disable colored output |

## Exit Codes

- `0` - No secrets found
- `1` - Secrets found
- `2` - Error occurred

## Tips

1. **Start Small**: Use `--max-files` to test on a subset first
2. **Review Test Files**: Test files often trigger many detections
3. **Check Documentation**: Doc examples may look like real secrets
4. **Pattern Specificity**: More specific patterns = fewer false positives
5. **Context Matters**: Always review the actual line to confirm if it's sensitive

## Known False Positives

Based on our testing, these are common false positives:

1. **Pattern Definitions**: Regex patterns in `secrets_scanner_hook.py` lines 66-67
2. **Test Data**: All findings in `read_hook_test.py` (intentional test secrets)
3. **Documentation**: Example credentials in README files
4. **Variable Names**: Variables like `api_key = "placeholder"`

To reduce these, you can:
- Add file-specific exclusions
- Make patterns more specific
- Add negative lookahead assertions to regex

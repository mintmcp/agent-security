# Testing and Tuning

This document covers how to run the included tests and adjust patterns.

## Run Tests

```bash
python3 plugins/secrets_scanner/tests/read_hook_test.py --suite all
```

Suites available: `basic`, `extended`, `exitcodes`, or `all`.

## Adjust Patterns

Edit `PATTERNS` in `plugins/secrets_scanner/hooks/secrets_scanner_hook.py` to refine detection or add new formats. Re-run tests after changes.

## Notes

- Regex detection is best-effort and may produce false positives. Review lines before acting.
- Post-execution hooks warn only; they cannot block a completed operation.

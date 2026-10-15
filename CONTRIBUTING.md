# Contributing to Athar

Thanks for your interest. Athar is a research prototype by Khafi Labs; reviews and critical feedback are as valuable as code.

## Ground rules
1. **No overclaiming.** Code, docs and receipts must not claim compliance, certification or proof beyond what tests demonstrate.
2. **Verifier changes need attack tests** (see `tests/attack/`). The verifier must fail closed.
3. **Legal rules need primary sources.** A jurisdiction rule must cite the statute or instruction, article and the date you read it. If unsure, set `period_confirmed=False` so erasure stays blocked.
4. Keep the verifier free of dependencies on the vault/keystore.

## Workflow
```bash
pip install -e ".[dev]"
ruff check . && ruff format --check . && mypy src && pytest
python -m demo.quickfin
```
Open a pull request using the template. By contributing you agree your contribution is licensed under Apache-2.0.

## Conduct
See CODE_OF_CONDUCT.md.

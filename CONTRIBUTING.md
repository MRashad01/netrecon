# Contributing to netrecon

Thanks for considering a contribution. This project is small and dependency-free on purpose — keep that in mind for any change.

## Setup

```bash
git clone https://github.com/MRashad01/netrecon
cd netrecon
pip install -e ".[dev]"
```

## Before opening a PR

```bash
pytest
ruff check .
```

Both run in CI on every PR — please make sure they pass locally first.

## Guidelines

- No new runtime dependencies without discussion — the zero-dependency design is a feature.
- Tests for scanner/parsing logic run against local loopback servers only; no external network access in the test suite.
- Keep the CLI's output stable — other tools and scripts may parse it.

## Good first issues

Check the [issue tracker](https://github.com/MRashad01/netrecon/issues) for anything labeled `good first issue`.

# Contributing

## Principles

- keep SurfaceLens local-first
- preserve analyst explainability over opaque scoring
- prefer additive imports over replacing existing recon tools
- avoid dependencies unless they clearly unlock meaningful value

## Development Workflow

1. Create a focused branch.
2. Make the smallest coherent change that improves import coverage, ranking, or exports.
3. Add or update sample data when behavior changes.
4. Run:

```bash
PYTHONPATH=src python3 -m unittest discover -s tests
python3 -m compileall src tests
```

5. Update the README or backlog if user-facing behavior changed.

## Code Style

- Python standard library first for core paths
- explicit, typed data flow over ad hoc dictionaries when practical
- explainable heuristics with clear reasons in output
- no silent destructive behavior on analyst data

## Pull Requests

A good pull request should answer:

- what workflow pain does this solve?
- what inputs or outputs changed?
- how was it verified?
- what assumptions or limitations remain?

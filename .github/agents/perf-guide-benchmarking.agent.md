---
name: Benchmarking Performance Changes
description: Measure and validate performance improvements
---

# Benchmarking Performance Changes

## Why Benchmark?

**SECURITY STORY**: Without measurements, "optimizations" can make things worse. A 10ms delay seems small until you scan 10,000 emails—then it's 100 seconds. Benchmarks catch regressions before production.

## Quick Start

**Install**:
```bash
pip install pytest-benchmark
```

**Pattern**: Always measure BEFORE and AFTER:

```python
def test_email_parsing_performance(benchmark):
    msg = create_test_email(parts=50)
    result = benchmark(parse_email, msg)

    # Security: Ensure reasonable time (DoS protection)
    assert benchmark.stats.mean < 0.1  # 100ms per email
```

## Real Example

See `tests/test_ingestion_optimization.py`:
- Tests O(N) string concatenation fix
- Validates multipart email speed
- **WHAT NOT TO DO**: Don't optimize without proof

## Best Practices

1. **Realistic Data**: Use actual email sizes from production
2. **Multiple Runs**: pytest-benchmark auto-warms and iterates
3. **Save Baseline**: `--benchmark-autosave` for comparisons
4. **Test Edge Cases**: 10MB emails, 100+ parts, nested MIME

## Interpreting Results

```bash
pytest tests/test_my_opt.py --benchmark-only
```

Key metrics:
- **Mean**: Average time (primary target)
- **StdDev**: Consistency (high = unstable)
- **Min/Max**: Outliers (huge max = DoS risk)

**MAINTENANCE WISDOM**: Add `assert benchmark.stats.mean < THRESHOLD` to catch CI regressions.

## Common Pitfalls

- In-memory tests miss disk I/O bottlenecks
- Small data hides O(N²) algorithms
- Over-mocking creates unrealistic results

**Professional teams**: Benchmarks in CI, fail PRs regressing >10%.

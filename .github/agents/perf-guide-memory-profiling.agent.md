---
name: Memory Profiling for Attachments
description: Identify and fix memory issues in processing
---

# Memory Profiling for Attachments

## Why Profile Memory?

**SECURITY STORY**: Attacker sends 10×50MB attachments. Without profiling, your code might load all 500MB simultaneously, hitting Docker limits and crashing. Profiling reveals attack surface.

## Quick Start

**Install**:
```bash
pip install memory_profiler psutil
```

**Pattern**: Profile hot paths:

```python
from memory_profiler import profile

@profile
def process_attachments(email):
    attachments = []
    for part in email.walk():
        if part.get_content_disposition() == 'attachment':
            # BAD: Loads entire attachment
            data = part.get_payload(decode=True)
            attachments.append(data)
    return attachments
```

Run: `python -m memory_profiler src/modules/media_analyzer.py`

## Interpreting Output

```
Line  Mem usage  Increment  Line Contents
3     50.2 MiB   0.0 MiB    data = part.get_payload(decode=True)
4     150.5 MiB  100.3 MiB  attachments.append(data)  # PROBLEM
```

**Red flag**: 100MB per attachment = 1GB for 10 attachments!

## Fix: Stream Instead

```python
def process_attachment_safely(part):
    # get_payload(decode=True) returns the full decoded bytes for this part
    payload = part.get_payload(decode=True)
    chunk_size = 1024 * 1024  # 1MB chunks

    # Process the payload in fixed-size chunks to keep peak memory bounded
    for i in range(0, len(payload), chunk_size):
        chunk = payload[i:i + chunk_size]
        analyze_chunk(chunk)  # Incremental analysis
```

**MAINTENANCE WISDOM**: Peak = base + chunk_size × workers. 3 workers × 1MB = 3MB peak vs 500MB loading all.

## Real Example

Docker limits: 512M-1G (README.md)
- **Current**: In-memory works for <10MB emails
- **Future**: Streaming for 50MB+ attachments

## Testing

```python
import tracemalloc

tracemalloc.start()
process_large_email()
current, peak = tracemalloc.get_traced_memory()
tracemalloc.stop()

assert peak < 100 * 1024 * 1024  # <100MB
```

## Common Issues

- **Hidden copies**: `data[:]` creates full copy
- **Circular refs**: Use `gc.get_referrers()`
- **Caching**: Limit size or truncate inputs (see NLP optimization)

**Professional teams**: Profile before production, set budgets, monitor with alerts.

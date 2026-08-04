2025-02-14:
- **Learning**: Doing pre-checks inside batched iterations via IMAP adds one network roundtrip per batch (RTT), scaling linearly with batch count and increasing latency.
- **Action**: Optimize by running a single upfront `_check_email_sizes()` on all fetched `email_ids` before slicing into batches, significantly reducing overall execution time (from 1.01s to 0.56s).

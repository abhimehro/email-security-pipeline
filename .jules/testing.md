## 2026-06-01 - Testing Asyncio Retry Logic
**Pattern:** Using `unittest.IsolatedAsyncioTestCase` and `unittest.mock.AsyncMock`.
**Learning:** When testing complex retry and backoff logic in Python `async` functions, use `IsolatedAsyncioTestCase` coupled with `patch` on `asyncio.sleep` to substitute it with an `AsyncMock`. This skips real-world sleeping (keeping tests fast) but still allows verifying that `await asyncio.sleep(X)` was called with the correct backoff interval values using `.assert_called_with()` or checking `.call_count`. 
**Action:** Always mock delays/sleeps in unit tests. Use `AsyncMock` with `side_effect` lists to simulate transient failures (e.g., `side_effect=[Exception("fail"), None]`) and test retry loops effectively.

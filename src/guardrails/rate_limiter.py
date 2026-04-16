"""
Lab 11 — Rate Limiter Plugin
Assignment 11 component: Sliding-window per-user rate limiter.

WHY A RATE LIMITER?
  No other guardrail prevents *volume* abuse. An attacker can send thousands
  of probing requests per minute to brute-force guardrail blind spots or
  exhaust API quota. The rate limiter is the first gate in the pipeline —
  it acts before any LLM call, making it essentially free to run.
"""
import time
from collections import defaultdict, deque

from google.adk.agents.invocation_context import InvocationContext
from google.adk.plugins import base_plugin
from google.genai import types


class RateLimitPlugin(base_plugin.BasePlugin):
    """Sliding-window per-user rate limiter.

    Tracks a deque of request timestamps per user_id.
    On each incoming message it:
      1. Evicts timestamps older than `window_seconds` from the front.
      2. If the deque length >= `max_requests`: blocks and returns a wait-time message.
      3. Otherwise: appends the current timestamp and allows the request through.

    WHY SLIDING WINDOW (not fixed window)?
      Fixed windows allow a burst of 2× max_requests at window boundaries.
      A sliding window guarantees *at most* max_requests in any rolling period.
    """

    def __init__(self, max_requests: int = 10, window_seconds: int = 60):
        """Initialize the rate limiter.

        Args:
            max_requests: Maximum number of requests allowed per user per window.
            window_seconds: Length of the sliding window in seconds.
        """
        super().__init__(name="rate_limiter")
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        # Per-user deque of request timestamps (float, UNIX epoch)
        self.user_windows: dict[str, deque] = defaultdict(deque)

        # Counters for monitoring
        self.blocked_count = 0
        self.total_count = 0
        self.rate_limit_hits: list[dict] = []  # Details of every block event

    def _get_user_id(self, invocation_context) -> str:
        """Extract user_id from ADK InvocationContext.

        Falls back to 'anonymous' so the limiter still works even when
        the context is None (e.g., during unit tests).
        """
        if invocation_context is None:
            return "anonymous"
        return getattr(invocation_context, "user_id", "anonymous") or "anonymous"

    async def on_user_message_callback(
        self,
        *,
        invocation_context: InvocationContext,
        user_message: types.Content,
    ) -> types.Content | None:
        """Enforce the rate limit before the message reaches the LLM.

        Returns:
            None if the request is within the limit (allow through).
            types.Content with a block message if the limit is exceeded.
        """
        user_id = self._get_user_id(invocation_context)
        now = time.time()
        window = self.user_windows[user_id]
        self.total_count += 1

        # Evict expired timestamps from the sliding window
        while window and window[0] < now - self.window_seconds:
            window.popleft()

        if len(window) >= self.max_requests:
            # Calculate how many seconds until the oldest request expires
            wait_seconds = int(window[0] + self.window_seconds - now) + 1
            self.blocked_count += 1
            self.rate_limit_hits.append(
                {
                    "user_id": user_id,
                    "timestamp": now,
                    "request_count_in_window": len(window),
                    "wait_seconds": wait_seconds,
                }
            )
            return types.Content(
                role="model",
                parts=[
                    types.Part.from_text(
                        text=(
                            f"[BLOCKED by Rate Limiter]\n"
                            f"You have sent {len(window)} requests in the last "
                            f"{self.window_seconds} seconds (limit: {self.max_requests}).\n"
                            f"Please wait {wait_seconds} second(s) before trying again."
                        )
                    )
                ],
            )

        # Under the limit — record this timestamp and allow through
        window.append(now)
        return None

    def get_stats(self) -> dict:
        """Return a summary of rate-limiter activity for monitoring."""
        return {
            "total_requests": self.total_count,
            "rate_limited": self.blocked_count,
            "rate_limit_rate": (
                self.blocked_count / self.total_count if self.total_count else 0.0
            ),
            "active_users": len(self.user_windows),
            "recent_hits": self.rate_limit_hits[-5:],  # Last 5 block events
        }


# ============================================================
# Quick test
# ============================================================

async def test_rate_limiter():
    """Send 15 rapid requests from the same user — first 10 pass, last 5 blocked."""
    plugin = RateLimitPlugin(max_requests=10, window_seconds=60)
    dummy_message = types.Content(
        role="user", parts=[types.Part.from_text(text="What is the interest rate?")]
    )

    class FakeContext:
        user_id = "test_user"

    print("Testing RateLimitPlugin (limit=10, window=60s):")
    print("=" * 60)
    for i in range(1, 16):
        result = await plugin.on_user_message_callback(
            invocation_context=FakeContext(), user_message=dummy_message
        )
        status = "BLOCKED" if result else "PASSED"
        print(f"  Request #{i:02d}: {status}")

    stats = plugin.get_stats()
    print(f"\nStats: {stats['rate_limited']} blocked / {stats['total_requests']} total")
    print("=" * 60)


if __name__ == "__main__":
    import sys
    from pathlib import Path
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

    import asyncio
    asyncio.run(test_rate_limiter())

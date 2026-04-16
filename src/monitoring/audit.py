"""
Lab 11 — Audit Log & Monitoring Alerts
Assignment 11 components:
  - AuditLogPlugin: Record every interaction (input, output, blocked, latency)
  - MonitoringAlert: Track metrics and fire alerts when thresholds are exceeded

WHY AUDIT + MONITORING?
  Guardrails stop known attacks, but monitoring reveals *unknown* threats.
  An audit trail is mandatory for regulated industries (banking, healthcare):
  you must be able to prove exactly what your AI said to whom and when.
  Alerts let you respond to anomalies in real time rather than post-mortem.
"""
import json
import time
from datetime import datetime

from google.adk.plugins import base_plugin
from google.genai import types


# ============================================================
# AuditLogPlugin
# ============================================================

class AuditLogPlugin(base_plugin.BasePlugin):
    """Record every interaction before and after the LLM.

    Uses the ADK two-callback pattern:
      on_user_message_callback  — records input + start time (never blocks)
      after_model_callback      — records output + latency (never modifies)

    WHY TWO CALLBACKS?
      The input callback fires before guardrail decisions; the output callback
      fires after. Together they capture the full lifecycle of each request,
      including which layer blocked it and how long each step took.
    """

    def __init__(self):
        super().__init__(name="audit_log")
        self.logs: list[dict] = []
        # Keyed by (user_id, session_id) to match input→output pairs
        self._pending: dict[str, dict] = {}
        # Monitoring counters (read by MonitoringAlert)
        self.blocked_count = 0
        self.total_count = 0

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _extract_text(self, content: types.Content) -> str:
        """Pull plain text out of a types.Content object."""
        if content is None:
            return ""
        text = ""
        for part in (content.parts or []):
            if hasattr(part, "text") and part.text:
                text += part.text
        return text

    def _pending_key(self, invocation_context) -> str:
        """Build a deduplication key from context."""
        if invocation_context is None:
            return "unknown"
        user_id = getattr(invocation_context, "user_id", "anon")
        session_id = getattr(invocation_context, "session_id", "?")
        return f"{user_id}::{session_id}"

    def _callback_key(self, callback_context) -> str:
        """Build the same key from after_model_callback's context."""
        if callback_context is None:
            return "unknown"
        # ADK uses InvocationContext here too, exposed via .invocation_context
        inv = getattr(callback_context, "invocation_context", callback_context)
        user_id = getattr(inv, "user_id", "anon")
        session_id = getattr(inv, "session_id", "?")
        return f"{user_id}::{session_id}"

    # ------------------------------------------------------------------
    # ADK callbacks
    # ------------------------------------------------------------------

    async def on_user_message_callback(
        self,
        *,
        invocation_context,
        user_message: types.Content,
    ):
        """Record input and start time. Never blocks."""
        self.total_count += 1
        key = self._pending_key(invocation_context)
        self._pending[key] = {
            "timestamp": datetime.now().isoformat(),
            "user_id": getattr(invocation_context, "user_id", "anon") if invocation_context else "anon",
            "session_id": getattr(invocation_context, "session_id", "?") if invocation_context else "?",
            "input": self._extract_text(user_message),
            "input_length": len(self._extract_text(user_message)),
            "start_time": time.perf_counter(),
            "output": None,
            "output_length": 0,
            "latency_ms": 0,
            "blocked": False,
            "blocked_by": None,
        }
        return None  # Never block

    async def after_model_callback(
        self,
        *,
        callback_context,
        llm_response,
    ):
        """Record output and compute latency. Never modifies the response."""
        key = self._callback_key(callback_context)
        entry = self._pending.pop(key, None)

        output = ""
        if hasattr(llm_response, "content") and llm_response.content:
            output = self._extract_text(llm_response.content)

        # Determine if this response was blocked by any upstream guardrail
        blocked = False
        blocked_by = None
        for marker, layer in [
            ("[BLOCKED by Rate Limiter]", "rate_limiter"),
            ("[BLOCKED by Input Guardrail", "input_guardrail"),
            ("[BLOCKED by Output Guardrail", "output_guardrail"),
        ]:
            if marker in output:
                blocked = True
                blocked_by = layer
                break

        if entry is None:
            # No matching input record — create a minimal entry
            entry = {
                "timestamp": datetime.now().isoformat(),
                "user_id": "unknown",
                "session_id": "unknown",
                "input": "",
                "input_length": 0,
                "start_time": time.perf_counter(),
            }

        latency_ms = int((time.perf_counter() - entry.pop("start_time")) * 1000)

        entry.update(
            {
                "output": output[:500],         # Truncate long responses
                "output_length": len(output),
                "latency_ms": latency_ms,
                "blocked": blocked,
                "blocked_by": blocked_by,
            }
        )

        self.logs.append(entry)
        if blocked:
            self.blocked_count += 1

        return llm_response  # Never modify

    # ------------------------------------------------------------------
    # Export
    # ------------------------------------------------------------------

    def export_json(self, filepath: str = "audit_log.json") -> str:
        """Export all log entries to a JSON file.

        Args:
            filepath: Output path for the JSON file.

        Returns:
            The filepath that was written.
        """
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(self.logs, f, indent=2, default=str, ensure_ascii=False)
        print(f"Audit log exported → {filepath}  ({len(self.logs)} entries)")
        return filepath

    def get_summary(self) -> dict:
        """Return a high-level summary suitable for monitoring."""
        total = len(self.logs)
        blocked = sum(1 for e in self.logs if e.get("blocked"))
        avg_latency = (
            sum(e.get("latency_ms", 0) for e in self.logs) / total
            if total else 0
        )
        by_layer: dict[str, int] = {}
        for entry in self.logs:
            layer = entry.get("blocked_by")
            if layer:
                by_layer[layer] = by_layer.get(layer, 0) + 1
        return {
            "total_requests": total,
            "blocked": blocked,
            "passed": total - blocked,
            "block_rate": blocked / total if total else 0.0,
            "avg_latency_ms": round(avg_latency, 1),
            "blocks_by_layer": by_layer,
        }


# ============================================================
# MonitoringAlert
# ============================================================

class MonitoringAlert:
    """Compute pipeline metrics and fire alerts when thresholds are exceeded.

    WHY A SEPARATE MONITORING CLASS (not more plugin logic)?
      Guardrail plugins should do one thing: block or modify requests.
      Metrics aggregation is a cross-cutting concern — it reads from
      multiple plugins and is run on-demand, not per-request. Keeping
      it separate follows the Single Responsibility Principle and makes
      it easy to swap in Prometheus/Datadog later.
    """

    def __init__(
        self,
        plugins: list,
        block_rate_threshold: float = 0.30,
        rate_limit_threshold: int = 5,
        judge_fail_threshold: float = 0.20,
    ):
        """Initialize the monitor.

        Args:
            plugins: List of all BasePlugin instances in the pipeline.
            block_rate_threshold: Alert if input block rate exceeds this fraction.
            rate_limit_threshold: Alert if this many rate-limit blocks have fired.
            judge_fail_threshold: Alert if LLM-judge fail rate exceeds this fraction.
        """
        # Index plugins by name for O(1) lookup
        self.plugins = {p.name: p for p in plugins if hasattr(p, "name")}
        self.block_rate_threshold = block_rate_threshold
        self.rate_limit_threshold = rate_limit_threshold
        self.judge_fail_threshold = judge_fail_threshold
        self.alerts: list[dict] = []

    def check_metrics(self) -> list[dict]:
        """Evaluate all metrics and return a list of triggered alerts.

        Checks:
          1. Input guardrail block rate
          2. Rate-limiter block count
          3. Output guardrail / LLM-judge fail rate
          4. Audit log presence (at least 1 entry)

        Returns:
            List of alert dicts, each with 'type', 'value', 'threshold', 'message'.
        """
        alerts: list[dict] = []

        # --- 1. Input guardrail block rate ---
        input_g = self.plugins.get("input_guardrail")
        if input_g and getattr(input_g, "total_count", 0) > 0:
            rate = input_g.blocked_count / input_g.total_count
            if rate > self.block_rate_threshold:
                alerts.append(
                    {
                        "type": "HIGH_INPUT_BLOCK_RATE",
                        "value": f"{rate:.1%}",
                        "threshold": f"{self.block_rate_threshold:.1%}",
                        "message": (
                            f"Input guardrail blocked {rate:.1%} of requests "
                            f"(threshold {self.block_rate_threshold:.1%}) — "
                            "possible attack spike or over-zealous regex."
                        ),
                    }
                )

        # --- 2. Rate-limiter block count ---
        rate_limiter = self.plugins.get("rate_limiter")
        if rate_limiter and getattr(rate_limiter, "blocked_count", 0) >= self.rate_limit_threshold:
            alerts.append(
                {
                    "type": "RATE_LIMIT_SPIKE",
                    "value": rate_limiter.blocked_count,
                    "threshold": self.rate_limit_threshold,
                    "message": (
                        f"{rate_limiter.blocked_count} rate-limit blocks recorded "
                        f"(threshold {self.rate_limit_threshold}) — "
                        "possible DDoS, scraping, or credential stuffing."
                    ),
                }
            )

        # --- 3. Output guardrail / LLM-judge fail rate ---
        output_g = self.plugins.get("output_guardrail")
        if output_g and getattr(output_g, "total_count", 0) > 0:
            judge_rate = output_g.blocked_count / output_g.total_count
            if judge_rate > self.judge_fail_threshold:
                alerts.append(
                    {
                        "type": "HIGH_JUDGE_FAIL_RATE",
                        "value": f"{judge_rate:.1%}",
                        "threshold": f"{self.judge_fail_threshold:.1%}",
                        "message": (
                            f"LLM judge failed {judge_rate:.1%} of responses "
                            f"(threshold {self.judge_fail_threshold:.1%}) — "
                            "the main model may be misbehaving."
                        ),
                    }
                )

        # --- 4. Audit log sanity check ---
        audit = self.plugins.get("audit_log")
        if audit is not None and len(getattr(audit, "logs", [])) == 0:
            alerts.append(
                {
                    "type": "AUDIT_LOG_EMPTY",
                    "value": 0,
                    "threshold": 1,
                    "message": "Audit log is empty — AuditLogPlugin may not be firing correctly.",
                }
            )

        self.alerts = alerts
        self._print_report(alerts)
        return alerts

    def _print_report(self, alerts: list[dict]):
        """Print a human-readable monitoring report to stdout."""
        print("\n" + "=" * 60)
        print("MONITORING REPORT")
        print("=" * 60)

        # Per-plugin stats
        for name, plugin in self.plugins.items():
            total = getattr(plugin, "total_count", None)
            blocked = getattr(plugin, "blocked_count", 0)
            if total:
                rate = blocked / total if total else 0
                print(f"  {name:20s}: {blocked:4d} blocked / {total:4d} total  ({rate:.1%})")

        # Audit log summary
        audit = self.plugins.get("audit_log")
        if audit and hasattr(audit, "get_summary"):
            summary = audit.get_summary()
            print(f"\n  Audit entries  : {summary['total_requests']}")
            print(f"  Avg latency    : {summary['avg_latency_ms']} ms")
            print(f"  Blocks by layer: {summary['blocks_by_layer']}")

        # Alerts
        if alerts:
            print(f"\n  *** {len(alerts)} ALERT(S) ***")
            for a in alerts:
                print(f"  [!] {a['type']}: {a['message']}")
        else:
            print("\n  OK — all metrics within thresholds.")

        print("=" * 60)


# ============================================================
# Quick test
# ============================================================

def test_audit_and_monitoring():
    """Smoke-test summary and alert logic with dummy data."""
    # Simulate an audit plugin that has logged 10 entries
    class FakeAudit:
        name = "audit_log"
        total_count = 10
        blocked_count = 4
        logs = [{"blocked": i < 4, "blocked_by": "input_guardrail", "latency_ms": 80} for i in range(10)]

        def get_summary(self):
            return {
                "total_requests": 10,
                "blocked": 4,
                "passed": 6,
                "block_rate": 0.4,
                "avg_latency_ms": 80.0,
                "blocks_by_layer": {"input_guardrail": 4},
            }

    class FakeInput:
        name = "input_guardrail"
        total_count = 10
        blocked_count = 4

    class FakeRateLimiter:
        name = "rate_limiter"
        total_count = 15
        blocked_count = 5

    monitor = MonitoringAlert(
        plugins=[FakeAudit(), FakeInput(), FakeRateLimiter()],
        block_rate_threshold=0.30,
        rate_limit_threshold=5,
    )
    alerts = monitor.check_metrics()
    print(f"\nAlerts fired: {len(alerts)}")


if __name__ == "__main__":
    test_audit_and_monitoring()

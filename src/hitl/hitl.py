"""
Lab 11 — Part 4: Human-in-the-Loop Design
  TODO 12: Confidence Router
  TODO 13: Design 3 HITL decision points
"""
from dataclasses import dataclass


# ============================================================
# TODO 12: Implement ConfidenceRouter
#
# Route agent responses based on confidence scores:
#   - HIGH (>= 0.9): Auto-send to user
#   - MEDIUM (0.7 - 0.9): Queue for human review
#   - LOW (< 0.7): Escalate to human immediately
#
# Special case: if the action is HIGH_RISK (e.g., money transfer,
# account deletion), ALWAYS escalate regardless of confidence.
#
# Implement the route() method.
# ============================================================

HIGH_RISK_ACTIONS = [
    "transfer_money",
    "close_account",
    "change_password",
    "delete_data",
    "update_personal_info",
]


@dataclass
class RoutingDecision:
    """Result of the confidence router."""
    action: str          # "auto_send", "queue_review", "escalate"
    confidence: float
    reason: str
    priority: str        # "low", "normal", "high"
    requires_human: bool


class ConfidenceRouter:
    """Route agent responses based on confidence and risk level.

    Thresholds:
        HIGH:   confidence >= 0.9 -> auto-send
        MEDIUM: 0.7 <= confidence < 0.9 -> queue for review
        LOW:    confidence < 0.7 -> escalate to human

    High-risk actions always escalate regardless of confidence.
    """

    HIGH_THRESHOLD = 0.9
    MEDIUM_THRESHOLD = 0.7

    def route(self, response: str, confidence: float,
              action_type: str = "general") -> RoutingDecision:
        """Route a response based on confidence score and action type.

        Args:
            response: The agent's response text
            confidence: Confidence score between 0.0 and 1.0
            action_type: Type of action (e.g., "general", "transfer_money")

        Returns:
            RoutingDecision with routing action and metadata
        """
        # Rule 1: High-risk actions always require a human, regardless of
        # how confident the model is. The cost of a wrong auto-decision
        # (e.g., an accidental $50,000 transfer) is too high to automate.
        if action_type in HIGH_RISK_ACTIONS:
            return RoutingDecision(
                action="escalate",
                confidence=confidence,
                reason=f"High-risk action: {action_type}",
                priority="high",
                requires_human=True,
            )

        # Rule 2: Route by confidence threshold.
        if confidence >= self.HIGH_THRESHOLD:
            return RoutingDecision(
                action="auto_send",
                confidence=confidence,
                reason="High confidence",
                priority="low",
                requires_human=False,
            )
        elif confidence >= self.MEDIUM_THRESHOLD:
            return RoutingDecision(
                action="queue_review",
                confidence=confidence,
                reason="Medium confidence — needs review",
                priority="normal",
                requires_human=True,
            )
        else:
            return RoutingDecision(
                action="escalate",
                confidence=confidence,
                reason="Low confidence — escalating",
                priority="high",
                requires_human=True,
            )


# ============================================================
# TODO 13: Design 3 HITL decision points
#
# For each decision point, define:
# - trigger: What condition activates this HITL check?
# - hitl_model: Which model? (human-in-the-loop, human-on-the-loop,
#   human-as-tiebreaker)
# - context_needed: What info does the human reviewer need?
# - example: A concrete scenario
#
# Think about real banking scenarios where human judgment is critical.
# ============================================================

hitl_decision_points = [
    {
        "id": 1,
        "name": "Large / Unusual Money Transfer",
        # Trigger: any transfer request above 50 million VND, or to an
        # account that has never received money from this customer before.
        # Automated approval would be catastrophic if the agent or customer
        # is compromised — a human must confirm the intent.
        "trigger": (
            "action_type == 'transfer_money' AND "
            "(amount > 50_000_000 VND OR recipient_account is new)"
        ),
        "hitl_model": "human-in-the-loop",  # Human must approve BEFORE money moves
        "context_needed": (
            "Customer ID, account balance, transfer amount, recipient account, "
            "last 5 transactions for pattern comparison, and customer's device/IP."
        ),
        "example": (
            "Customer requests a 200,000,000 VND wire to an overseas account "
            "never used before. Agent flags it; a fraud analyst reviews and "
            "calls the customer to confirm before approving."
        ),
    },
    {
        "id": 2,
        "name": "Low-Confidence or Ambiguous Response",
        # Trigger: confidence score from ConfidenceRouter falls in the
        # MEDIUM band (0.7–0.9) OR the LLM judge flags accuracy concerns.
        # Better to queue for review than to send a potentially wrong
        # answer about loan rates or regulatory requirements.
        "trigger": (
            "confidence < 0.9 OR llm_judge.accuracy_score < 3"
        ),
        "hitl_model": "human-on-the-loop",  # Human reviews async; response is held
        "context_needed": (
            "The user's question, the agent's draft response, the judge scores "
            "(safety / relevance / accuracy / tone), and the relevant FAQ excerpt."
        ),
        "example": (
            "Customer asks about early loan repayment penalties. "
            "The agent gives a general answer with confidence 0.78. "
            "A customer service rep reviews within 2 minutes and either "
            "approves or rewrites the response before it is sent."
        ),
    },
    {
        "id": 3,
        "name": "Suspected Security Incident / Repeated Attack Attempts",
        # Trigger: the same user_id triggers the injection guardrail 3+
        # times in a single session, or the session anomaly score crosses
        # a threshold. This signals active adversarial probing.
        "trigger": (
            "injection_blocks_in_session >= 3 OR session_anomaly_score > 0.8"
        ),
        "hitl_model": "human-as-tiebreaker",
        # Security team decides: lock the account, rate-limit, or flag as
        # a false positive (e.g., penetration tester with proper auth).
        "context_needed": (
            "Full session transcript, user_id, IP address, all blocked messages "
            "with the matched guardrail pattern, and account risk score."
        ),
        "example": (
            "A user sends 4 messages within 60 seconds, each a variation of "
            "'ignore all previous instructions'. The session is paused and "
            "a security analyst reviews the transcript to decide whether to "
            "lock the account or mark it as authorized red-team activity."
        ),
    },
]


# ============================================================
# Quick tests
# ============================================================

def test_confidence_router():
    """Test ConfidenceRouter with sample scenarios."""
    router = ConfidenceRouter()

    test_cases = [
        ("Balance inquiry", 0.95, "general"),
        ("Interest rate question", 0.82, "general"),
        ("Ambiguous request", 0.55, "general"),
        ("Transfer $50,000", 0.98, "transfer_money"),
        ("Close my account", 0.91, "close_account"),
    ]

    print("Testing ConfidenceRouter:")
    print("=" * 80)
    print(f"{'Scenario':<25} {'Conf':<6} {'Action Type':<18} {'Decision':<15} {'Priority':<10} {'Human?'}")
    print("-" * 80)

    for scenario, conf, action_type in test_cases:
        decision = router.route(scenario, conf, action_type)
        print(
            f"{scenario:<25} {conf:<6.2f} {action_type:<18} "
            f"{decision.action:<15} {decision.priority:<10} "
            f"{'Yes' if decision.requires_human else 'No'}"
        )

    print("=" * 80)


def test_hitl_points():
    """Display HITL decision points."""
    print("\nHITL Decision Points:")
    print("=" * 60)
    for point in hitl_decision_points:
        print(f"\n  Decision Point #{point['id']}: {point['name']}")
        print(f"    Trigger:  {point['trigger']}")
        print(f"    Model:    {point['hitl_model']}")
        print(f"    Context:  {point['context_needed']}")
        print(f"    Example:  {point['example']}")
    print("\n" + "=" * 60)


if __name__ == "__main__":
    test_confidence_router()
    test_hitl_points()

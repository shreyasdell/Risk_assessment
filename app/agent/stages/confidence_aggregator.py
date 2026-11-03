"""
Stage 5: Confidence Aggregator & Final Decision

Aggregates results from all previous stages and produces a final
decision about whether to display a CVE in the UI.

Decision Matrix:
┌────────────┬────────────┬────────────┬────────────┬──────────────┐
│ CPE Match  │ Ecosystem  │ Version    │ LLM        │ Final        │
├────────────┼────────────┼────────────┼────────────┼──────────────┤
│ MATCH      │ any        │ IN_RANGE   │ not needed │ RELEVANT ✓   │
│ MATCH      │ any        │ OUT_RANGE  │ not needed │ NOT_REL  ✗   │
│ NO_MATCH   │ any        │ any        │ not needed │ NOT_REL  ✗   │
│ UNCERTAIN  │ NO_MATCH   │ any        │ not needed │ NOT_REL  ✗   │
│ UNCERTAIN  │ UNCERTAIN  │ any        │ MATCH      │ RELEVANT ✓   │
│ UNCERTAIN  │ UNCERTAIN  │ any        │ NO_MATCH   │ NOT_REL  ✗   │
│ UNCERTAIN  │ UNCERTAIN  │ any        │ UNCERTAIN  │ NEEDS_REVIEW │
└────────────┴────────────┴────────────┴────────────┴──────────────┘
"""

from dataclasses import dataclass, field
from typing import List, Optional, Dict
import logging

from app.agent.stages.cpe_matcher import MatchVerdict, StageResult

logger = logging.getLogger(__name__)


@dataclass
class AggregatedResult:
    """Final result for a single CVE after passing through all stages."""
    cve_id: str
    final_verdict: str          # "RELEVANT", "NOT_RELEVANT", "NEEDS_REVIEW"
    final_confidence: int       # 0-100
    should_display: bool        # Whether to show in the UI
    stage_results: List[dict]   # Detailed results from each stage
    summary: str                # Human-readable summary of the decision
    processing_time: float = 0.0  # Time taken to process (seconds)


class ConfidenceAggregator:
    """
    Aggregates results from all pipeline stages and produces
    a final verdict with confidence score.
    """

    # Stage weights for weighted confidence calculation
    STAGE_WEIGHTS: Dict[str, float] = {
        "cpe_matcher":        0.40,   # Highest — most reliable signal
        "purl_resolver":      0.25,   # Second — ecosystem mismatch is strong
        "version_validator":  0.20,   # Third — version range check
        "llm_reasoner":       0.15,   # Lowest — supplementary only
    }

    # Minimum confidence to display in UI
    DISPLAY_THRESHOLD: int = 50

    # Above this confidence, no manual review needed
    AUTO_APPROVE_THRESHOLD: int = 75

    def aggregate(
        self,
        cve_id: str,
        stage_results: Dict[str, Optional[StageResult]],
    ) -> AggregatedResult:
        """
        Aggregate results from all stages into a final decision.

        Args:
            cve_id: CVE identifier string.
            stage_results: Dict mapping stage name to its StageResult.
                           Values may be None if stage was not executed.

        Returns:
            AggregatedResult with final verdict and reasoning.
        """
        cpe = stage_results.get("cpe_matcher")
        purl = stage_results.get("purl_resolver")
        version = stage_results.get("version_validator")
        llm = stage_results.get("llm_reasoner")

        # ────────────────────────────────────────────────────────
        #  Fast-path decisions (deterministic, no LLM needed)
        # ────────────────────────────────────────────────────────

        # 1. CPE definitive NO_MATCH → reject
        if cpe and cpe.verdict == MatchVerdict.NO_MATCH and cpe.confidence >= 70:
            return self._build_result(
                cve_id=cve_id,
                verdict="NOT_RELEVANT",
                confidence=cpe.confidence,
                should_display=False,
                stages=stage_results,
                summary=f"Rejected by CPE analysis: {cpe.reasoning}",
            )

        # 2. Ecosystem mismatch → reject
        if purl and purl.verdict == MatchVerdict.NO_MATCH and purl.confidence >= 70:
            return self._build_result(
                cve_id=cve_id,
                verdict="NOT_RELEVANT",
                confidence=purl.confidence,
                should_display=False,
                stages=stage_results,
                summary=f"Rejected by ecosystem analysis: {purl.reasoning}",
            )

        # 3. CPE MATCH + version IN_RANGE → accept
        if (cpe and cpe.verdict == MatchVerdict.MATCH
                and version and version.verdict == MatchVerdict.MATCH):
            combined_confidence = min(cpe.confidence, version.confidence)
            return self._build_result(
                cve_id=cve_id,
                verdict="RELEVANT",
                confidence=combined_confidence,
                should_display=True,
                stages=stage_results,
                summary=(
                    f"Confirmed: CPE product match with version in affected range. "
                    f"{cpe.reasoning}"
                ),
            )

        # 4. CPE MATCH + version OUT_OF_RANGE → reject
        if (cpe and cpe.verdict == MatchVerdict.MATCH
                and version and version.verdict == MatchVerdict.NO_MATCH):
            return self._build_result(
                cve_id=cve_id,
                verdict="NOT_RELEVANT",
                confidence=version.confidence,
                should_display=False,
                stages=stage_results,
                summary=(
                    f"Product matches but version is not affected. "
                    f"{version.reasoning}"
                ),
            )

        # 5. CPE MATCH + version UNCERTAIN → accept with lower confidence
        if cpe and cpe.verdict == MatchVerdict.MATCH:
            return self._build_result(
                cve_id=cve_id,
                verdict="RELEVANT",
                confidence=max(cpe.confidence - 15, 50),
                should_display=True,
                stages=stage_results,
                summary=(
                    f"CPE product match confirmed but version range "
                    f"could not be validated. {cpe.reasoning}"
                ),
            )

        # ────────────────────────────────────────────────────────
        #  LLM-assisted decisions
        # ────────────────────────────────────────────────────────

        if llm and llm.verdict != MatchVerdict.UNCERTAIN:
            weighted_conf = self._calculate_weighted_confidence(stage_results)

            if llm.verdict == MatchVerdict.MATCH:
                return self._build_result(
                    cve_id=cve_id,
                    verdict="RELEVANT",
                    confidence=weighted_conf,
                    should_display=weighted_conf >= self.DISPLAY_THRESHOLD,
                    stages=stage_results,
                    summary=f"LLM-confirmed relevant: {llm.reasoning}",
                )
            else:
                return self._build_result(
                    cve_id=cve_id,
                    verdict="NOT_RELEVANT",
                    confidence=weighted_conf,
                    should_display=False,
                    stages=stage_results,
                    summary=f"LLM-rejected as not relevant: {llm.reasoning}",
                )

        # ────────────────────────────────────────────────────────
        #  Fallback: Everything uncertain
        # ────────────────────────────────────────────────────────

        return self._build_result(
            cve_id=cve_id,
            verdict="NEEDS_REVIEW",
            confidence=25,
            should_display=True,  # Show for manual review
            stages=stage_results,
            summary=(
                "Insufficient data for automated decision. "
                "All analysis stages returned uncertain results. "
                "Manual review recommended."
            ),
        )

    def _calculate_weighted_confidence(
        self, stage_results: Dict[str, Optional[StageResult]]
    ) -> int:
        """
        Calculate a weighted confidence score from all stages.

        MATCH verdicts contribute positively.
        NO_MATCH verdicts contribute negatively (inverted).
        UNCERTAIN verdicts contribute neutrally (50).
        """
        total_weight = 0.0
        weighted_sum = 0.0

        for stage_name, weight in self.STAGE_WEIGHTS.items():
            result = stage_results.get(stage_name)
            if result is None or result.confidence == 0:
                continue

            if result.verdict == MatchVerdict.MATCH:
                adjusted = result.confidence
            elif result.verdict == MatchVerdict.NO_MATCH:
                # Invert: high-confidence NO_MATCH = low relevance score
                adjusted = 100 - result.confidence
            else:
                adjusted = 50  # Neutral for UNCERTAIN

            weighted_sum += adjusted * weight
            total_weight += weight

        if total_weight == 0:
            return 25  # Default low confidence

        return int(weighted_sum / total_weight)

    def _build_result(
        self,
        cve_id: str,
        verdict: str,
        confidence: int,
        should_display: bool,
        stages: Dict[str, Optional[StageResult]],
        summary: str,
    ) -> AggregatedResult:
        """Build the final AggregatedResult object."""
        stage_details = []
        for name in ["cpe_matcher", "purl_resolver", "version_validator", "llm_reasoner"]:
            result = stages.get(name)
            if result is not None:
                stage_details.append({
                    "stage": name,
                    "verdict": result.verdict.value,
                    "confidence": result.confidence,
                    "reasoning": result.reasoning,
                    "matched_cpe": getattr(result, "matched_cpe", None),
                })
            else:
                stage_details.append({
                    "stage": name,
                    "verdict": "SKIPPED",
                    "confidence": 0,
                    "reasoning": "Stage was not executed (early termination or not needed).",
                    "matched_cpe": None,
                })

        return AggregatedResult(
            cve_id=cve_id,
            final_verdict=verdict,
            final_confidence=max(0, min(100, confidence)),
            should_display=should_display,
            stage_results=stage_details,
            summary=summary,
        )

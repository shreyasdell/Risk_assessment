"""
CVE Filtering Agent — Main Orchestrator

Orchestrates the multi-stage CVE filtering pipeline:
    Stage 0: CVE.org Enrichment (NEW, fetches CPE data from MITRE)
    Stage 1: CPE Matcher       (deterministic, fast)
    Stage 2: PURL Resolver     (deterministic, fast)
    Stage 3: Version Validator (deterministic, fast)
    Stage 4: LLM Reasoner     (Qwen via Ollama, slow — conditional)
    Stage 5: Confidence Aggregator (fast)

Design principles:
1. CVE.org enrichment first — provides CPE data that NVD often lacks
2. Deterministic stages run next — they are fast and reliable
3. LLM is invoked ONLY for ambiguous cases — it's slow and costly
4. Early termination when a stage is decisive
5. Every decision includes full reasoning for auditability
6. The pipeline is idempotent — safe to re-run on the same data
"""

import time
import logging
import asyncio
from typing import List, Dict, Optional

from app.agent.stages.cpe_matcher import CPEMatcher, MatchVerdict, StageResult
from app.agent.stages.purl_resolver import PURLResolver
from app.agent.stages.version_validator import VersionValidator
from app.agent.stages.llm_reasoner import LLMReasoner
from app.agent.stages.confidence_aggregator import ConfidenceAggregator, AggregatedResult
from app.services.cve_org_service import cve_org_client

logger = logging.getLogger(__name__)


class CVEFilterAgent:
    """
    Main orchestrator for the CVE filtering pipeline.

    Usage:
        agent = CVEFilterAgent()
        results = agent.filter_cves(component, raw_cves_from_nvd)
        # results contains only CVEs that should be displayed

    The agent processes each CVE through up to 5 stages:
    1. If Stage 1 gives a definitive answer (confidence >= 80), stop.
    2. If Stage 2 gives a definitive answer (confidence >= 80), stop.
    3. Run Stage 3 (version check).
    4. If all deterministic stages are inconclusive, run Stage 4 (LLM).
    5. Aggregate all results in Stage 5.
    """

    # Confidence threshold for early termination
    EARLY_TERMINATION_THRESHOLD = 80

    def __init__(
        self,
        ollama_url: str = "http://localhost:11434",
        model: str = "qwen2.5:7b",
        ollama_timeout: int = 60,
        display_threshold: int = 50,
        enable_cve_org: bool = True,
    ):
        """
        Initialize the CVE filtering agent.

        Args:
            ollama_url: URL of the local Ollama server.
            model: Qwen model name in Ollama (e.g., "qwen2.5:7b").
            ollama_timeout: Timeout for Ollama API calls in seconds.
            display_threshold: Minimum confidence to display a CVE in UI.
            enable_cve_org: Whether to use CVE.org enrichment (Stage 0).
        """
        self.cpe_matcher = CPEMatcher()
        self.purl_resolver = PURLResolver()
        self.version_validator = VersionValidator()
        self.enable_cve_org = enable_cve_org
        self.llm_reasoner = LLMReasoner(
            ollama_url=ollama_url,
            model=model,
            timeout=ollama_timeout,
        )
        self.aggregator = ConfidenceAggregator()
        self.aggregator.DISPLAY_THRESHOLD = display_threshold

        logger.info(
            f"CVEFilterAgent initialized (model={model}, "
            f"display_threshold={display_threshold}, enable_cve_org={enable_cve_org})"
        )

    def filter_cves(
        self,
        component: dict,
        raw_cves: List[dict],
    ) -> List[AggregatedResult]:
        """
        Filter a list of raw CVEs from NVD API and return only relevant ones.

        Args:
            component: Component metadata dict. Expected keys:
                {
                    "name": "carbon",
                    "version": "2.1.1",
                    "purl": "pkg:npm/carbon@2.1.1",    # optional but recommended
                    "ecosystem": "npm"                   # optional, derived from PURL
                }
            raw_cves: List of CVE objects from the NVD API response.
                      Each item may be wrapped in {"cve": {...}} (NVD v2 format)
                      or be a raw CVE dict.

        Returns:
            List of AggregatedResult objects where should_display=True,
            sorted by confidence (highest first).
        """
        if not raw_cves:
            logger.debug(f"No CVEs to filter for component '{component.get('name')}'")
            return []

        # Ensure ecosystem is set (derive from PURL if missing)
        component = self._enrich_component(component)

        all_results: List[AggregatedResult] = []
        stats = {"total": 0, "stage1_reject": 0, "stage2_reject": 0,
                 "deterministic_accept": 0, "llm_invoked": 0, "displayed": 0}

        for cve_item in raw_cves:
            # NVD API v2 wraps CVE data in "cve" key
            cve = cve_item.get("cve", cve_item) if isinstance(cve_item, dict) else cve_item
            # Try both "id" (NVD API format) and "cve_id" (our processed format)
            cve_id = cve.get("id") or cve.get("cve_id", "Unknown")
            stats["total"] += 1

            start_time = time.time()

            result = self._process_single_cve(component, cve, cve_id, stats)
            result.processing_time = round(time.time() - start_time, 4)

            all_results.append(result)

        # Filter to displayable results
        displayable = [r for r in all_results if r.should_display]
        displayable.sort(key=lambda r: r.final_confidence, reverse=True)
        stats["displayed"] = len(displayable)

        logger.info(
            f"CVE filtering complete for '{component.get('name')}': "
            f"total={stats['total']}, "
            f"stage1_reject={stats['stage1_reject']}, "
            f"stage2_reject={stats['stage2_reject']}, "
            f"deterministic_accept={stats['deterministic_accept']}, "
            f"llm_invoked={stats['llm_invoked']}, "
            f"displayed={stats['displayed']}"
        )

        return displayable

    def filter_cves_full(
        self,
        component: dict,
        raw_cves: List[dict],
    ) -> List[AggregatedResult]:
        """
        Same as filter_cves but returns ALL results (including rejected ones).
        Useful for debugging, auditing, and testing.
        """
        if not raw_cves:
            return []

        component = self._enrich_component(component)
        all_results = []
        stats = {"total": 0, "stage1_reject": 0, "stage2_reject": 0,
                 "deterministic_accept": 0, "llm_invoked": 0, "displayed": 0}

        for cve_item in raw_cves:
            cve = cve_item.get("cve", cve_item) if isinstance(cve_item, dict) else cve_item
            # Try both "id" (NVD API format) and "cve_id" (our processed format)
            cve_id = cve.get("id") or cve.get("cve_id", "Unknown")
            stats["total"] += 1

            start_time = time.time()
            result = self._process_single_cve(component, cve, cve_id, stats)
            result.processing_time = round(time.time() - start_time, 4)
            all_results.append(result)

        all_results.sort(key=lambda r: r.final_confidence, reverse=True)
        return all_results

    # ──────────────────────────────────────────────────────────────
    #  Internal pipeline
    # ──────────────────────────────────────────────────────────────

    def _process_single_cve(
        self,
        component: dict,
        cve: dict,
        cve_id: str,
        stats: dict,
    ) -> AggregatedResult:
        """Process a single CVE through the pipeline."""

        stage_results: Dict[str, Optional[StageResult]] = {
            "cpe_matcher": None,
            "purl_resolver": None,
            "version_validator": None,
            "llm_reasoner": None,
        }

        # ── STAGE 0: CVE.org Enrichment (NEW) ──────────────────
        if self.enable_cve_org:
            try:
                # Run async CVE.org fetch in sync context
                loop = asyncio.get_event_loop()
                cve_org_data = loop.run_until_complete(
                    cve_org_client.fetch_cve(cve_id)
                )
                
                if cve_org_data:
                    parsed = cve_org_client.parse_cve_record(cve_org_data)
                    is_affected, confidence, reason = cve_org_client.is_component_affected(
                        parsed,
                        component.get("name", ""),
                        component.get("version", ""),
                        component.get("purl")
                    )
                    
                    # High confidence result from CVE.org - early termination
                    if confidence >= 80:
                        logger.info(f"[CVE.org] {cve_id}: {reason} (confidence: {confidence})")
                        # Create a StageResult for CVE.org
                        cve_org_result = StageResult(
                            verdict=MatchVerdict.MATCH if is_affected else MatchVerdict.NO_MATCH,
                            confidence=confidence,
                            reasoning=reason,
                            matched_cpe=parsed.get("affected_products", [{}])[0].get("cpes", [""])[0] if parsed.get("affected_products") else None
                        )
                        stage_results["cpe_matcher"] = cve_org_result
                        return self.aggregator.aggregate(cve_id, stage_results)
                    else:
                        logger.debug(f"[CVE.org] {cve_id}: Low confidence ({confidence}), continuing to pipeline")
                        # Enrich CVE data with CPEs from CVE.org for CPE matcher
                        if parsed.get("affected_products"):
                            cpe_list = []
                            for prod in parsed["affected_products"]:
                                cpe_list.extend(prod.get("cpes", []))
                            if cpe_list:
                                cve["configurations"] = {"nodes": [{"cpeMatch": cpe_list}]}
                                logger.debug(f"[CVE.org] Enriched {cve_id} with {len(cpe_list)} CPEs")
            except Exception as e:
                logger.debug(f"[CVE.org] Error fetching {cve_id}: {e}, continuing to pipeline")

        # ── STAGE 1: CPE Matching ──────────────────────────────
        cpe_result = self.cpe_matcher.evaluate(component, cve)
        stage_results["cpe_matcher"] = cpe_result

        # Early termination: CPE definitive NO_MATCH
        if (cpe_result.verdict == MatchVerdict.NO_MATCH
                and cpe_result.confidence >= self.EARLY_TERMINATION_THRESHOLD):
            stats["stage1_reject"] += 1
            logger.debug(f"{cve_id}: Rejected at Stage 1 (CPE). {cpe_result.reasoning}")
            return self.aggregator.aggregate(cve_id, stage_results)

        # ── STAGE 2: PURL Ecosystem Check ──────────────────────
        purl_result = self.purl_resolver.evaluate(component, cve)
        stage_results["purl_resolver"] = purl_result

        # Early termination: Ecosystem mismatch
        if (purl_result.verdict == MatchVerdict.NO_MATCH
                and purl_result.confidence >= self.EARLY_TERMINATION_THRESHOLD):
            stats["stage2_reject"] += 1
            logger.debug(f"{cve_id}: Rejected at Stage 2 (PURL). {purl_result.reasoning}")
            return self.aggregator.aggregate(cve_id, stage_results)

        # ── STAGE 3: Version Range Validation ──────────────────
        version_result = self.version_validator.evaluate(component, cve)
        stage_results["version_validator"] = version_result

        # Check if deterministic stages are sufficient
        if self._deterministic_stages_decisive(cpe_result, purl_result, version_result):
            if cpe_result.verdict == MatchVerdict.MATCH:
                stats["deterministic_accept"] += 1
            logger.debug(
                f"{cve_id}: Resolved deterministically. "
                f"CPE={cpe_result.verdict.value}, "
                f"PURL={purl_result.verdict.value}, "
                f"Version={version_result.verdict.value}"
            )
            return self.aggregator.aggregate(cve_id, stage_results)

        # ── STAGE 4: LLM Reasoning (conditional) ──────────────
        needs_llm = self._needs_llm_analysis(cpe_result, purl_result, version_result)
        
        logger.debug(f"{cve_id}: needs_llm={needs_llm}, cpe={cpe_result.verdict.value if cpe_result else 'None'}, purl={purl_result.verdict.value if purl_result else 'None'}, version={version_result.verdict.value if version_result else 'None'}")

        if needs_llm:
            stats["llm_invoked"] += 1
            logger.debug(f"{cve_id}: Invoking LLM for ambiguous case.")
            llm_result = self.llm_reasoner.evaluate(component, cve)
            stage_results["llm_reasoner"] = llm_result

        # ── STAGE 5: Aggregate and decide ──────────────────────
        return self.aggregator.aggregate(cve_id, stage_results)

    def _deterministic_stages_decisive(
        self,
        cpe_result: StageResult,
        purl_result: StageResult,
        version_result: StageResult,
    ) -> bool:
        """
        Check if the deterministic stages have produced a clear-enough
        signal that the LLM is not needed.
        """
        # If any stage has high-confidence definitive answer
        for result in [cpe_result, purl_result, version_result]:
            if (result.confidence >= self.EARLY_TERMINATION_THRESHOLD
                    and result.verdict != MatchVerdict.UNCERTAIN):
                return True

        # CPE MATCH + version in range → definitely decisive
        if (cpe_result.verdict == MatchVerdict.MATCH
                and version_result.verdict == MatchVerdict.MATCH):
            return True

        # CPE MATCH + version out of range → decisive
        if (cpe_result.verdict == MatchVerdict.MATCH
                and version_result.verdict == MatchVerdict.NO_MATCH):
            return True

        return False

    def _needs_llm_analysis(
        self,
        cpe_result: StageResult,
        purl_result: StageResult,
        version_result: StageResult,
    ) -> bool:
        """
        Determine if LLM analysis is needed.

        LLM is invoked when:
        1. All deterministic stages returned UNCERTAIN
        2. Stages conflict with each other
        3. Confidence is low across all stages
        """
        results = [cpe_result, purl_result, version_result]
        verdicts = [r.verdict for r in results]

        # If all stages are uncertain → need LLM
        if all(v == MatchVerdict.UNCERTAIN for v in verdicts):
            return True

        # If stages conflict → need LLM as tiebreaker
        match_count = verdicts.count(MatchVerdict.MATCH)
        no_match_count = verdicts.count(MatchVerdict.NO_MATCH)
        if match_count > 0 and no_match_count > 0:
            return True

        # If no stage has high confidence → need LLM
        max_confidence = max(r.confidence for r in results)
        if max_confidence < 50:
            return True

        return False

    def _enrich_component(self, component: dict) -> dict:
        """
        Enrich the component dict by deriving ecosystem from PURL
        if not already set.
        """
        enriched = dict(component)  # Shallow copy

        if not enriched.get("ecosystem") and enriched.get("purl"):
            purl = enriched["purl"]
            if purl.startswith("pkg:"):
                try:
                    purl_type = purl[4:purl.index("/")]
                    enriched["ecosystem"] = purl_type.lower()
                except ValueError:
                    pass

        return enriched

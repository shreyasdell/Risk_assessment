"""
Stage 4: LLM Reasoner (Qwen via Ollama)

This stage is ONLY invoked when the deterministic stages (CPE matcher,
PURL resolver, version validator) return UNCERTAIN. It uses a locally
running Qwen model through Ollama to perform contextual reasoning
about whether a CVE is genuinely relevant to a component.

Design decisions:
- Confidence is CAPPED at 75 because LLM output is non-deterministic
  and less reliable than CPE/PURL matching.
- Temperature is set very low (0.1) for consistency.
- The prompt explicitly warns against keyword-matching traps.
- Response format is enforced as JSON for reliable parsing.
"""

import json
import re
import requests
from typing import Optional
import logging

from app.agent.stages.cpe_matcher import MatchVerdict, StageResult

logger = logging.getLogger(__name__)


class LLMReasoner:
    """
    Stage 4: LLM-based contextual reasoning for ambiguous CVE matches.
    Uses Qwen model running locally via Ollama.
    """

    # Maximum confidence score the LLM stage can assign.
    # This is intentionally lower than deterministic stages
    # because LLM output is probabilistic.
    MAX_LLM_CONFIDENCE = 75

    SYSTEM_PROMPT = """You are a cybersecurity vulnerability analyst specializing in
Software Bill of Materials (SBOM) analysis. Your job is to determine whether a
CVE (Common Vulnerabilities and Exposures) entry is genuinely relevant to a
specific software component.

You must respond ONLY with a valid JSON object. No markdown, no explanation
outside the JSON. Just the JSON object.

CRITICAL ANALYSIS RULES:

1. A CVE is RELEVANT only if the vulnerability actually exists in the
   component's codebase or its direct dependencies.

2. Keyword matches in CVE descriptions are NOT sufficient evidence.
   The description contains narrative context that often mentions
   unrelated things.

3. Hardware device names in descriptions (e.g., "ThinkPad X1 Carbon",
   "Dell Latitude", "HP ProBook") do NOT mean the CVE affects a
   software package with a similar name.

4. File paths (e.g., /usr/lib/carbon/...) are NOT indicators that
   a package called "carbon" is affected.

5. Reporter/discoverer names are NOT indicators of affected products.

6. Always check the ECOSYSTEM. An npm package is fundamentally different
   from a Linux kernel module, a C library, or a Java application,
   even if they share the same name.

7. Focus on the "Affected Products" (CPE entries) — these are the
   authoritative source for what software is actually affected.

REQUIRED JSON RESPONSE FORMAT:
{
    "is_relevant": true or false,
    "confidence": 0 to 100,
    "reasoning": "Clear, specific explanation of your decision",
    "affected_product": "The actual product/software this CVE affects",
    "component_product": "The SBOM component being evaluated",
    "match_type": "one of: exact_match | different_product | different_ecosystem | incidental_mention | unknown"
}"""

    def __init__(
        self,
        ollama_url: str = "http://localhost:11434",
        model: str = "qwen2.5:7b",
        timeout: int = 60,
    ):
        """
        Initialize the LLM reasoner.

        Args:
            ollama_url: URL of the Ollama API server.
            model: Model name to use (must be pulled in Ollama).
            timeout: Request timeout in seconds.
        """
        self.ollama_url = ollama_url.rstrip("/")
        self.model = model
        self.timeout = timeout

    def evaluate(self, component: dict, cve: dict) -> StageResult:
        """
        Use LLM to reason about CVE-component relevance.

        This method is designed to be called only for ambiguous cases
        where deterministic stages returned UNCERTAIN.

        Args:
            component: Component dict.
            cve: Raw CVE object from NVD API.

        Returns:
            StageResult with LLM's verdict and reasoning.
        """
        # Check if Ollama is available
        if not self._check_ollama_health():
            return StageResult(
                verdict=MatchVerdict.UNCERTAIN,
                confidence=0,
                reasoning="Ollama service is not available; LLM analysis skipped.",
            )

        # Build the analysis prompt
        prompt = self._build_prompt(component, cve)

        try:
            # Call Ollama API
            raw_response = self._call_ollama(prompt)

            if not raw_response:
                return StageResult(
                    verdict=MatchVerdict.UNCERTAIN,
                    confidence=0,
                    reasoning="LLM returned empty response.",
                )

            # Parse LLM response
            parsed = self._parse_llm_response(raw_response)

            if not parsed:
                logger.warning(
                    f"Could not parse LLM response for CVE "
                    f"{cve.get('id', 'unknown')}: {raw_response[:200]}"
                )
                return StageResult(
                    verdict=MatchVerdict.UNCERTAIN,
                    confidence=0,
                    reasoning=(
                        "LLM response could not be parsed as JSON. "
                        f"Raw response (truncated): {raw_response[:200]}"
                    ),
                )

            # Convert LLM output to StageResult
            is_relevant = parsed.get("is_relevant", False)
            llm_confidence = min(
                parsed.get("confidence", 50),
                self.MAX_LLM_CONFIDENCE,
            )
            llm_reasoning = parsed.get("reasoning", "No reasoning provided.")
            match_type = parsed.get("match_type", "unknown")
            affected_product = parsed.get("affected_product", "unknown")

            if is_relevant:
                return StageResult(
                    verdict=MatchVerdict.MATCH,
                    confidence=llm_confidence,
                    reasoning=(
                        f"[LLM] Relevant (match_type: {match_type}). "
                        f"{llm_reasoning}"
                    ),
                )
            else:
                return StageResult(
                    verdict=MatchVerdict.NO_MATCH,
                    confidence=llm_confidence,
                    reasoning=(
                        f"[LLM] Not relevant (match_type: {match_type}). "
                        f"CVE affects '{affected_product}', not component "
                        f"'{component.get('name', 'unknown')}'. "
                        f"{llm_reasoning}"
                    ),
                )

        except requests.exceptions.Timeout:
            logger.warning(f"Ollama request timed out after {self.timeout}s")
            return StageResult(
                verdict=MatchVerdict.UNCERTAIN,
                confidence=0,
                reasoning=f"LLM inference timed out after {self.timeout} seconds.",
            )
        except requests.exceptions.ConnectionError:
            logger.warning("Cannot connect to Ollama service")
            return StageResult(
                verdict=MatchVerdict.UNCERTAIN,
                confidence=0,
                reasoning="Cannot connect to Ollama service.",
            )
        except Exception as e:
            logger.error(f"LLM stage error: {e}", exc_info=True)
            return StageResult(
                verdict=MatchVerdict.UNCERTAIN,
                confidence=0,
                reasoning=f"LLM stage encountered an error: {str(e)}",
            )

    # ──────────────────────────────────────────────────────────────
    #  Prompt construction
    # ──────────────────────────────────────────────────────────────

    def _build_prompt(self, component: dict, cve: dict) -> str:
        """Build the analysis prompt for the LLM."""
        cve_id = cve.get("id", "Unknown")

        # Extract English description
        description = ""
        descriptions = cve.get("descriptions", [])
        for desc in descriptions:
            if desc.get("lang") == "en":
                description = desc.get("value", "")
                break
        if not description and descriptions:
            description = descriptions[0].get("value", "")

        # Truncate long descriptions to stay within token limits
        max_desc_len = 1500
        if len(description) > max_desc_len:
            description = description[:max_desc_len] + "... [truncated]"

        # Extract affected products (CPE entries)
        affected_products = []
        for config in cve.get("configurations", []):
            for node in config.get("nodes", []):
                for cpe_match in node.get("cpeMatch", []):
                    criteria = cpe_match.get("criteria", "")
                    version_info = ""
                    if "versionStartIncluding" in cpe_match:
                        version_info += f" (from {cpe_match['versionStartIncluding']}"
                    if "versionEndExcluding" in cpe_match:
                        version_info += f" to {cpe_match['versionEndExcluding']})"
                    elif version_info:
                        version_info += ")"
                    affected_products.append(criteria + version_info)

        # Limit to first 10 CPE entries
        affected_products_str = "\n".join(
            f"  - {p}" for p in affected_products[:10]
        )
        if len(affected_products) > 10:
            affected_products_str += f"\n  ... and {len(affected_products) - 10} more"

        # Extract severity info
        metrics = cve.get("metrics", {})
        cvss_score = "N/A"
        severity = "N/A"
        for metric_key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
            metric_list = metrics.get(metric_key, [])
            if metric_list:
                cvss_data = metric_list[0].get("cvssData", {})
                cvss_score = cvss_data.get("baseScore", "N/A")
                severity = cvss_data.get("baseSeverity", "N/A")
                break

        return f"""Analyze whether this CVE is genuinely relevant to the given software component.

## Software Component Being Evaluated
- Name: {component.get('name', 'unknown')}
- Version: {component.get('version', 'unknown')}
- Package URL (PURL): {component.get('purl', 'not available')}
- Ecosystem: {component.get('ecosystem', 'unknown')}

## CVE Entry
- CVE ID: {cve_id}
- CVSS Score: {cvss_score} ({severity})
- Description:
  {description}

- Affected Products (CPE entries):
{affected_products_str if affected_products_str else '  None listed'}

## Your Task
Determine if CVE {cve_id} genuinely affects the software component
"{component.get('name', '')}" version "{component.get('version', '')}"
from the "{component.get('ecosystem', '')}" ecosystem.

Pay special attention to:
1. Does the CVE's affected product (CPE) match this component?
2. Is there an ecosystem mismatch? (e.g., npm package vs kernel module)
3. Is the component name mentioned only incidentally in the description
   (hardware name, file path, reporter name)?
4. Is the component version within the affected range?

Respond ONLY with the JSON object as specified in your instructions."""

    # ──────────────────────────────────────────────────────────────
    #  Ollama API interaction
    # ──────────────────────────────────────────────────────────────

    def _check_ollama_health(self) -> bool:
        """Check if Ollama is running and responsive."""
        try:
            response = requests.get(
                f"{self.ollama_url}/api/tags",
                timeout=5,
            )
            return response.status_code == 200
        except requests.exceptions.RequestException:
            return False

    def _call_ollama(self, prompt: str) -> Optional[str]:
        """
        Call the Ollama /api/generate endpoint.

        Returns the generated text or None on failure.
        """
        payload = {
            "model": self.model,
            "prompt": prompt,
            "system": self.SYSTEM_PROMPT,
            "stream": False,
            "options": {
                "temperature": 0.1,    # Very low for deterministic output
                "num_predict": 512,    # Max tokens to generate
                "top_p": 0.9,
                "top_k": 40,
                "repeat_penalty": 1.1,
            },
        }

        response = requests.post(
            f"{self.ollama_url}/api/generate",
            json=payload,
            timeout=self.timeout,
        )
        response.raise_for_status()

        result = response.json()
        return result.get("response", "")

    # ──────────────────────────────────────────────────────────────
    #  Response parsing
    # ──────────────────────────────────────────────────────────────

    def _parse_llm_response(self, response: str) -> Optional[dict]:
        """
        Parse JSON from LLM response, handling common formatting issues.

        LLMs sometimes wrap JSON in markdown code blocks or include
        extra text before/after the JSON.
        """
        response = response.strip()

        # Attempt 1: Direct JSON parse
        try:
            parsed = json.loads(response)
            if isinstance(parsed, dict):
                return self._validate_llm_output(parsed)
        except json.JSONDecodeError:
            pass

        # Attempt 2: Extract from markdown code block
        patterns = [
            r'```json\s*\n?(.*?)\n?\s*```',
            r'```\s*\n?(.*?)\n?\s*```',
        ]
        for pattern in patterns:
            match = re.search(pattern, response, re.DOTALL)
            if match:
                try:
                    parsed = json.loads(match.group(1).strip())
                    if isinstance(parsed, dict):
                        return self._validate_llm_output(parsed)
                except json.JSONDecodeError:
                    continue

        # Attempt 3: Find first { ... } block
        brace_match = re.search(r'\{[^{}]*\}', response, re.DOTALL)
        if brace_match:
            try:
                parsed = json.loads(brace_match.group(0))
                if isinstance(parsed, dict):
                    return self._validate_llm_output(parsed)
            except json.JSONDecodeError:
                pass

        # Attempt 4: Find nested { ... } block (handles nested braces)
        try:
            start = response.index("{")
            depth = 0
            for i in range(start, len(response)):
                if response[i] == "{":
                    depth += 1
                elif response[i] == "}":
                    depth -= 1
                    if depth == 0:
                        json_str = response[start:i + 1]
                        parsed = json.loads(json_str)
                        if isinstance(parsed, dict):
                            return self._validate_llm_output(parsed)
                        break
        except (ValueError, json.JSONDecodeError):
            pass

        return None

    def _validate_llm_output(self, parsed: dict) -> dict:
        """
        Validate and normalize the parsed LLM output.

        Ensures required fields exist with reasonable defaults.
        """
        # Normalize is_relevant to boolean
        is_relevant = parsed.get("is_relevant")
        if isinstance(is_relevant, str):
            is_relevant = is_relevant.lower() in ("true", "yes", "1")
        elif not isinstance(is_relevant, bool):
            is_relevant = False
        parsed["is_relevant"] = is_relevant

        # Normalize confidence to int 0-100
        confidence = parsed.get("confidence", 50)
        if isinstance(confidence, str):
            try:
                confidence = int(confidence)
            except ValueError:
                confidence = 50
        confidence = max(0, min(100, int(confidence)))
        parsed["confidence"] = confidence

        # Ensure reasoning exists
        if "reasoning" not in parsed or not parsed["reasoning"]:
            parsed["reasoning"] = "No detailed reasoning provided by LLM."

        # Ensure match_type exists
        valid_match_types = {
            "exact_match", "different_product",
            "different_ecosystem", "incidental_mention", "unknown",
        }
        if parsed.get("match_type") not in valid_match_types:
            parsed["match_type"] = "unknown"

        # Ensure affected_product exists
        if "affected_product" not in parsed:
            parsed["affected_product"] = "unknown"

        # Ensure component_product exists
        if "component_product" not in parsed:
            parsed["component_product"] = "unknown"

        return parsed

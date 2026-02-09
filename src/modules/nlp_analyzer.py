"""
Layer 2: NLP-Based Threat Detection
Uses transformer models to detect social engineering,
urgency markers, and psychological manipulation
"""

import re
import logging
from typing import List, Dict, Tuple, Optional
from collections import defaultdict
from dataclasses import dataclass
from functools import lru_cache

from .email_ingestion import EmailData

# Optional imports at module level
try:
    import torch
    from transformers import AutoTokenizer, AutoModelForSequenceClassification
except (ImportError, OSError):
    torch = None
    AutoTokenizer = None
    AutoModelForSequenceClassification = None


@dataclass
class NLPAnalysisResult:
    """Result of NLP analysis"""
    threat_score: float
    social_engineering_indicators: List[str]
    urgency_markers: List[str]
    authority_impersonation: List[str]
    psychological_triggers: List[str]
    risk_level: str


class NLPThreatAnalyzer:
    """NLP-based threat detection analyzer"""

    # Social engineering patterns
    SOCIAL_ENGINEERING_PATTERNS = [
        (r'\b(verify|confirm|update|validate)\s+(your\s+)?(account|password|information|details|credentials)\b',
         "Account verification request"),
        (r'\b(suspended|locked|disabled|restricted|blocked)\s+(account|access)\b',
         "Account suspension threat"),
        (r'\b(unusual|suspicious|unauthorized)\s+(activity|login|access|transaction)\b',
         "Suspicious activity claim"),
        (r'\b(security\s+)(alert|warning|notice|breach|threat)\b',
         "Security alert"),
        (r'\b(reset|change|update)\s+your\s+password\b',
         "Password reset request"),
    ]

    # Urgency markers
    URGENCY_PATTERNS = [
        (r'\b(urgent|immediate|asap|emergency|critical|time[-\s]sensitive)\b',
         "Urgency keyword"),
        (r'\b(within\s+\d+\s+(hours?|minutes?|days?))\b',
         "Time pressure"),
        (r'\b(expire[sd]?|expiring|expiration)\b',
         "Expiration warning"),
        (r'\b(act\s+now|respond\s+immediately|don\'t\s+delay)\b',
         "Action pressure"),
        (r'\b(limited\s+time|last\s+chance|final\s+(warning|notice))\b',
         "Scarcity tactic"),
    ]

    # Authority impersonation indicators
    AUTHORITY_PATTERNS = [
        (r'\b(bank|paypal|amazon|microsoft|apple|google|irs|fbi|police)\b',
         "Authority entity mention"),
        (r'\b(ceo|president|director|manager|supervisor|administrator)\b',
         "Authority title"),
        (r'\b(official|authorized|legitimate|certified)\b',
         "Authority claim"),
        (r'\b(government|federal|national|department of)\b',
         "Government entity"),
        (r'\b(court|legal|lawsuit|subpoena|warrant)\b',
         "Legal threat"),
    ]

    # Psychological triggers
    PSYCHOLOGICAL_PATTERNS = [
        (r'\b(free|bonus|gift|reward|prize|win|won|winner)\b',
         "Reward temptation"),
        (r'\b(fear|worry|concern|risk|danger|threat)\b',
         "Fear appeal"),
        (r'\b(opportunity|exclusive|special|limited)\b',
         "Exclusivity appeal"),
        (r'\b(guarantee|certified|approved|verified)\b',
         "Trust signal"),
        (r'\b(secret|confidential|private|insider)\b',
         "Secrecy appeal"),
    ]

    # Pre-compiled patterns for optimization
    CAPS_WORDS_PATTERN = re.compile(r'\b[A-Z]{4,}\b')
    SENDER_DOMAIN_PATTERN = re.compile(r'@([\w\.-]+)')

    def __init__(self, config):
        """
        Initialize NLP analyzer

        Args:
            config: AnalysisConfig object
        """
        self.config = config
        self.logger = logging.getLogger("NLPThreatAnalyzer")
        self.model = None
        self.tokenizer = None
        self.device = None

        # Compile combined master pattern for performance
        # We combine all regex patterns into a single master regex to scan the text
        all_patterns = []
        for p, d in self.SOCIAL_ENGINEERING_PATTERNS:
            all_patterns.append((p, "SE", d))
        for p, d in self.URGENCY_PATTERNS:
            all_patterns.append((p, "UG", d))
        for p, d in self.AUTHORITY_PATTERNS:
            all_patterns.append((p, "AU", d))
        for p, d in self.PSYCHOLOGICAL_PATTERNS:
            all_patterns.append((p, "PS", d))

        self.master_pattern, self.master_map = self._compile_master_pattern(all_patterns)
        self.simple_master_pattern = self._compile_simple_master_pattern(all_patterns)

        # Initialize model if needed
        if self._should_use_ml_model():
            self._initialize_model()

    def _compile_master_pattern(self, patterns: List[Tuple[str, str, str]]) \
            -> Tuple[re.Pattern, Dict[str, Tuple[str, str]]]:
        """
        Compile a list of regex patterns into a single combined regex.
        Returns the compiled regex and a mapping of group names to (prefix, description).
        """
        regex_parts = []
        group_map = {}
        prefix_counts: Dict[str, int] = defaultdict(int)
        for pattern, prefix, description in patterns:
            index = prefix_counts[prefix]
            prefix_counts[prefix] += 1
            group_name = f"{prefix}_{index}"
            # Wrap pattern in a named group.
            regex_parts.append(f"(?P<{group_name}>{pattern})")
            group_map[group_name] = (prefix, description)

        full_pattern = "|".join(regex_parts)
        return re.compile(full_pattern, re.IGNORECASE), group_map

    def _compile_simple_master_pattern(self, patterns: List[Tuple[str, str, str]]) -> re.Pattern:
        """
        Compile a simplified master pattern without named groups for fast presence check.
        """
        # Join patterns with OR operator, wrapped in non-capturing groups if needed
        # We rely on the fact that existing patterns capture what they need internally
        # but for the simple check we just need ANY match.
        regex_parts = []
        for pattern, _, _ in patterns:
            regex_parts.append(f"(?:{pattern})")

        full_pattern = "|".join(regex_parts)
        return re.compile(full_pattern, re.IGNORECASE)

    def _should_use_ml_model(self) -> bool:
        """Check if ML model should be loaded"""
        return True

    def _initialize_model(self):
        """Initialize transformer model"""
        if not torch:
            self.logger.warning("Torch/Transformers not installed. ML features disabled.")
            return

        try:
            model_name = getattr(
                self.config, 'nlp_model', 'distilbert-base-uncased'
            )
            self.tokenizer = AutoTokenizer.from_pretrained(model_name)
            self.model = AutoModelForSequenceClassification.from_pretrained(
                model_name
            )
            self.model.eval()
            self.device = next(self.model.parameters()).device
            self.logger.info(f"ML model initialized with {model_name} on {self.device}")
        except Exception as e:
            self.logger.warning(f"Could not load ML model: {e}")
            self.model = None
            self.tokenizer = None
            self.device = None

    def analyze(self, email_data: EmailData) -> NLPAnalysisResult:
        """
        Perform NLP analysis on email content

        Args:
            email_data: Email to analyze

        Returns:
            NLPAnalysisResult
        """
        threat_score = 0.0
        social_engineering = []
        urgency_markers = []
        authority_impersonation = []
        psychological_triggers = []

        # Combine text for analysis
        text = f"{email_data.subject} {email_data.body_text}"

        # Single pass scan
        matches_by_category = {
            "SE": defaultdict(int),
            "UG": defaultdict(int),
            "AU": defaultdict(list), # Authority needs the actual match strings
            "PS": defaultdict(int)
        }

        # Optimization: Fast check with simple pattern
        if self.simple_master_pattern.search(text):
            for match in self.master_pattern.finditer(text):
                group_name = match.lastgroup
                if group_name and group_name in self.master_map:
                    prefix, description = self.master_map[group_name]
                    if prefix == "AU":
                        matches_by_category[prefix][description].append(match.group())
                    else:
                        matches_by_category[prefix][description] += 1

        # Check for social engineering
        if self.config.check_social_engineering:
            score, indicators = self._detect_social_engineering(matches_by_category["SE"])
            threat_score += score
            social_engineering.extend(indicators)

        # Check for urgency markers
        if self.config.check_urgency_markers:
            score, indicators = self._detect_urgency(text, matches_by_category["UG"])
            threat_score += score
            urgency_markers.extend(indicators)

        # Check for authority impersonation
        if self.config.check_authority_impersonation:
            score, indicators = self._detect_authority_impersonation(
                email_data.sender, matches_by_category["AU"]
            )
            threat_score += score
            authority_impersonation.extend(indicators)

        # Detect psychological triggers
        if getattr(self.config, "check_psychological_triggers", False):
            score, indicators = self._detect_psychological_triggers(matches_by_category["PS"])
            threat_score += score
            psychological_triggers.extend(indicators)

        # Integration of Transformer Model Predictions into Threat Scoring
        if self.model and self.tokenizer:
            # We pass the original text to the transformer, not lowercased
            # as some models are case-sensitive (though distilbert-base-uncased isn't)
            transformer_results = self.analyze_with_transformer(text)
            if "error" not in transformer_results:
                ml_threat_prob = transformer_results.get("threat_probability", 0.0)

                # If the probability suggests a threat (>0.5), we increase the score.
                if ml_threat_prob > 0.5:
                    # Map 0.5-1.0 to 0-10 points
                    ml_score = (ml_threat_prob - 0.5) * 20
                    threat_score += ml_score
                    social_engineering.append(
                        f"ML Model detected high threat probability: "
                        f"{ml_threat_prob:.2f}"
                    )

        # Calculate risk level
        risk_level = self._calculate_risk_level(threat_score)

        self.logger.debug(
            f"NLP analysis complete: score={threat_score:.2f}, risk={risk_level}"
        )

        return NLPAnalysisResult(
            threat_score=threat_score,
            social_engineering_indicators=social_engineering,
            urgency_markers=urgency_markers,
            authority_impersonation=authority_impersonation,
            psychological_triggers=psychological_triggers,
            risk_level=risk_level
        )

    def _detect_social_engineering(self, counts: Dict[str, int]) -> Tuple[float, List[str]]:
        """Detect social engineering patterns"""
        score = 0.0
        indicators = []

        for description, count in counts.items():
            score += count * 2.0  # High weight for social engineering
            indicators.append(f"{description} ({count} occurrences)")

        return score, indicators

    def _detect_urgency(self, text: str, counts: Dict[str, int]) -> Tuple[float, List[str]]:
        """Detect urgency and time pressure tactics"""
        score = 0.0
        indicators = []

        for description, count in counts.items():
            score += count * 1.5
            indicators.append(f"{description} ({count} occurrences)")

        # Check for multiple exclamation marks (urgency indicator)
        exclamation_count = text.count('!')
        if exclamation_count > 2:
            score += exclamation_count * 0.5
            indicators.append(f"Excessive exclamation marks ({exclamation_count})")

        # Check for all caps words (shouting)
        # Using finditer instead of findall to avoid allocating full match list
        caps_word_count = sum(
            1 for _ in self.CAPS_WORDS_PATTERN.finditer(text)
        )
        if caps_word_count > 3:
            score += caps_word_count * 0.3
            indicators.append(f"Excessive caps words ({caps_word_count})")

        return score, indicators

    def _detect_authority_impersonation(self, sender: str, matches_by_desc: Dict[str, List[str]]) -> Tuple[float, List[str]]:
        """Detect authority impersonation attempts"""
        score = 0.0
        indicators = []

        sender_lower = sender.lower()
        sender_domain = ""
        # Using pre-compiled regex for performance
        domain_match = self.SENDER_DOMAIN_PATTERN.search(sender_lower)
        if domain_match:
            sender_domain = domain_match.group(1)

        for description, matches in matches_by_desc.items():
            authority_mismatch = False

            # Check if authority claim matches sender domain
            for match_text in matches:
                # Logic from original: if match.lower() not in sender_domain -> mismatch
                if sender_domain and match_text.lower() not in sender_domain:
                    authority_mismatch = True
                    break

            # Treat missing sender domain as suspicious when authority claims are present
            if not sender_domain and matches:
                authority_mismatch = True

            if authority_mismatch:
                score += len(matches) * 2.5  # High score for mismatch
                indicators.append(f"{description} (domain mismatch)")
            else:
                score += len(matches) * 0.5
                indicators.append(f"{description}")

        return score, indicators

    def _detect_psychological_triggers(self, counts: Dict[str, int]) -> Tuple[float, List[str]]:
        """Detect psychological manipulation tactics"""
        score = 0.0
        indicators = []

        for description, count in counts.items():
            score += count * 1.0
            indicators.append(f"{description} ({count} occurrences)")

        return score, indicators

    def _calculate_risk_level(self, score: float) -> str:
        """Calculate risk level based on NLP threat score"""
        threshold = self.config.nlp_threshold * 10  # Scale threshold

        if score >= threshold * 2:
            return "high"
        elif score >= threshold:
            return "medium"
        else:
            return "low"

    def analyze_with_transformer(self, text: str) -> Dict:
        """
        Analyze text using transformer model

        Args:
            text: Text to analyze

        Returns:
            Dictionary with analysis results
        """
        # Optimization: Truncate text before processing/caching
        # 4096 chars is ~1000 tokens, well above the 512 token limit of most models
        # This avoids hashing and processing huge strings for the cache key
        truncated_text = text[:4096]
        return self._analyze_with_transformer_core(truncated_text)

    @lru_cache(maxsize=1024)
    def _analyze_with_transformer_core(self, text: str) -> Dict:
        """
        Core transformer analysis with caching
        """
        if not self.model or not self.tokenizer:
            return {"error": "Model not loaded"}

        if not torch:
            return {"error": "Torch not available"}

        try:
            # Tokenize and predict
            inputs = self.tokenizer(
                text, return_tensors="pt", truncation=True, max_length=512
            )

            # Use cached device if available, otherwise fallback
            device = self.device if self.device else next(self.model.parameters()).device

            inputs = {k: v.to(device) for k, v in inputs.items()}

            with torch.no_grad():
                outputs = self.model(**inputs)
                predictions = torch.softmax(outputs.logits, dim=-1)

            # NOTE: The current model is a binary sentiment classifier (e.g., SST-2)
            # 0 = negative sentiment, 1 = positive sentiment.

            # Using the simplest interpretation as per original code context
            threat_prob = predictions[0][0].item()
            confidence = max(predictions[0]).item()

            return {
                "threat_probability": threat_prob,
                "confidence": confidence
            }
        except Exception as e:
            self.logger.error(f"Transformer analysis error: {e}")
            return {"error": str(e)}

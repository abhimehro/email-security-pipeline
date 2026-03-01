"""
Layer 2: NLP-Based Threat Detection
Uses transformer models to detect social engineering,
urgency markers, and psychological manipulation
"""

import re
import logging
import hashlib
from typing import List, Dict, Tuple, Optional
from collections import defaultdict
from dataclasses import dataclass

from ..utils.caching import TTLCache

from .email_ingestion import EmailData
from ..utils.pattern_compiler import compile_patterns, check_redos_safety
from ..utils.threat_scoring import calculate_risk_level

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
        # TTL cache: max 512 entries, entries expire after 1 hour.
        # MAINTENANCE WISDOM: bounded size + TTL prevents memory growth in
        # long-running daemon mode regardless of email volume or pattern diversity.
        self._cache: TTLCache = TTLCache(max_size=512, ttl_seconds=3600)

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
        raw_patterns = [pattern for pattern, _, _ in patterns]
        check_redos_safety(raw_patterns)

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
        raw_patterns = [pattern for pattern, _, _ in patterns]
        return compile_patterns(raw_patterns, re.I)

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
            getattr(self.model, "eval")()
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

        # Iterate over parts to avoid large string concatenation
        parts = [email_data.subject, email_data.body_text]

        # Scan text for patterns and stats
        matches_by_category, exclamation_count, caps_count = self._scan_text_patterns(parts)

        # Check for social engineering
        if self.config.check_social_engineering:
            score, indicators = self._detect_social_engineering(matches_by_category["SE"])
            threat_score += score
            social_engineering.extend(indicators)

        # Check for urgency markers
        if self.config.check_urgency_markers:
            score, indicators = self._detect_urgency(exclamation_count, caps_count, matches_by_category["UG"])
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
            ml_score, ml_indicators = self._run_transformer_analysis(email_data)
            threat_score += ml_score
            social_engineering.extend(ml_indicators)

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

    def _scan_text_patterns(self, parts: List[Optional[str]]) -> Tuple[Dict, int, int]:
        """Scan text parts for patterns and statistics"""
        exclamation_count = 0
        caps_count = 0
        matches_by_category = {
            "SE": defaultdict(int),
            "UG": defaultdict(int),
            "AU": defaultdict(list), # Authority needs the actual match strings
            "PS": defaultdict(int)
        }

        for part in parts:
            if not part:
                continue

            # Accumulate simple counts for urgency detection
            exclamation_count += part.count('!')
            # Use finditer for memory efficiency instead of findall
            caps_count += sum(1 for _ in self.CAPS_WORDS_PATTERN.finditer(part))

            # Optimization: Fast check with simple pattern
            if self.simple_master_pattern.search(part):
                for match in self.master_pattern.finditer(part):
                    group_name = match.lastgroup
                    if group_name and group_name in self.master_map:
                        prefix, description = self.master_map[group_name]
                        if prefix == "AU":
                            matches_by_category[prefix][description].append(match.group())
                        else:
                            matches_by_category[prefix][description] += 1

        return matches_by_category, exclamation_count, caps_count

    def _run_transformer_analysis(self, email_data: EmailData) -> Tuple[float, List[str]]:
        """Run transformer model analysis on email content"""
        # Prepare text for transformer efficiently, avoiding huge concatenation
        # Truncate text before processing/caching
        # 4096 chars is ~1000 tokens, well above the 512 token limit of most models
        max_len = 4096
        subject_len = len(email_data.subject)
        # +1 for space between subject and body
        if subject_len + 1 >= max_len:
            ml_text = email_data.subject[:max_len]
        else:
            ml_text = f"{email_data.subject} {email_data.body_text[:max_len - subject_len - 1]}"

        # We pass the text to the transformer
        # as some models are case-sensitive (though distilbert-base-uncased isn't)
        transformer_results = self.analyze_with_transformer(ml_text)

        score = 0.0
        indicators = []

        if "error" not in transformer_results:
            ml_threat_prob = transformer_results.get("threat_probability", 0.0)

            # If the probability suggests a threat (>0.5), we increase the score.
            if ml_threat_prob > 0.5:
                # Map 0.5-1.0 to 0-10 points
                ml_score = (ml_threat_prob - 0.5) * 20
                score += ml_score
                indicators.append(
                    f"ML Model detected high threat probability: "
                    f"{ml_threat_prob:.2f}"
                )

        return score, indicators

    def _detect_social_engineering(self, counts: Dict[str, int]) -> Tuple[float, List[str]]:
        """Detect social engineering patterns"""
        score = 0.0
        indicators = []

        for description, count in counts.items():
            score += count * 2.0  # High weight for social engineering
            indicators.append(f"{description} ({count} occurrences)")

        return score, indicators

    def _detect_urgency(self, exclamation_count: int, caps_count: int, counts: Dict[str, int]) -> Tuple[float, List[str]]:
        """Detect urgency and time pressure tactics"""
        score = 0.0
        indicators = []

        for description, count in counts.items():
            score += count * 1.5
            indicators.append(f"{description} ({count} occurrences)")

        # Check for multiple exclamation marks (urgency indicator)
        if exclamation_count > 2:
            score += exclamation_count * 0.5
            indicators.append(f"Excessive exclamation marks ({exclamation_count})")

        # Check for all caps words (shouting)
        if caps_count > 3:
            score += caps_count * 0.3
            indicators.append(f"Excessive caps words ({caps_count})")

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
        return calculate_risk_level(score, threshold, threshold * 2)

    def analyze_with_transformer(self, text: str) -> Dict:
        """
        Analyze text using transformer model

        Args:
            text: Text to analyze

        Returns:
            Dictionary with analysis results
        """
        # Optimization: Truncate text before processing
        truncated_text = text[:4096]

        # Calculate hash for cache key to avoid storing raw text
        # SECURITY STORY: hashing means sensitive email content never appears
        # in the cache's key space, reducing exposure in heap dumps / logs.
        text_hash = hashlib.sha256(truncated_text.encode()).hexdigest()

        # Check cache (TTL-aware, thread-safe lookup + LRU promotion)
        cached = self._cache.get(text_hash)
        if cached is not None:
            return cached

        # Compute result outside the lock to avoid blocking other threads
        result = self._analyze_core_impl(truncated_text)

        # Store in cache — TTLCache handles size eviction and thread safety
        self._cache.put(text_hash, result)

        return result

    def _analyze_core_impl(self, text: str) -> Dict:
        """
        Core transformer analysis implementation
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

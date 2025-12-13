"""
Layer 2: NLP-Based Threat Detection
Uses transformer models to detect social engineering, urgency markers, and psychological manipulation
"""

import re
import logging
from typing import List, Dict, Tuple
from dataclasses import dataclass
import torch

from .email_ingestion import EmailData


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
        
        # Initialize model if needed
        if self._should_use_ml_model():
            self._initialize_model()
    
    def _should_use_ml_model(self) -> bool:
        """Check if ML model should be loaded"""
        # We can now proceed with loading the transformer model
        return True
    
    def _initialize_model(self):
        """Initialize transformer model"""
        try:
            from transformers import AutoTokenizer, AutoModelForSequenceClassification
            self.tokenizer = AutoTokenizer.from_pretrained(self.config.nlp_model)
            self.model = AutoModelForSequenceClassification.from_pretrained(self.config.nlp_model)
            self.logger.info(f"ML model initialized: {self.config.nlp_model}")
        except Exception as e:
            self.logger.warning(f"Could not load ML model: {e}")
            self.model = None
            self.tokenizer = None
    
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
        text_lower = text.lower()
        
        # Check for social engineering
        if self.config.check_social_engineering:
            score, indicators = self._detect_social_engineering(text_lower)
            threat_score += score
            social_engineering.extend(indicators)
        
        # Check for urgency markers
        if self.config.check_urgency_markers:
            score, indicators = self._detect_urgency(text_lower)
            threat_score += score
            urgency_markers.extend(indicators)
        
        # Check for authority impersonation
        if self.config.check_authority_impersonation:
            score, indicators = self._detect_authority_impersonation(text_lower, email_data.sender)
            threat_score += score
            authority_impersonation.extend(indicators)
        
        # Detect psychological triggers
        score, indicators = self._detect_psychological_triggers(text_lower)
        threat_score += score
        psychological_triggers.extend(indicators)

        # Integration of Transformer Model Predictions into Threat Scoring
        # ---------------------------------------------------------------
        # If a transformer model and tokenizer are available, we analyze the email text using the model.
        # The model is expected to output a "threat probability" (between 0 and 1).
        # If the probability exceeds a threshold (0.5), we map the excess probability (ml_threat_prob - 0.5)
        # to a threat score increment (scaled to a maximum of 10 points for ml_threat_prob=1.0).
        # This is done via: ml_score = (ml_threat_prob - 0.5) * 20
        # The ML-derived score is then added to the overall threat_score.
        # 
        # Assumptions and Caveats:
        # - The default model ('distilbert-base-uncased') is not fine-tuned for threat detection,
        #   so its predictions may not be meaningful. The weighting is kept low and the logic is
        #   structured to allow for future use of a fine-tuned model.
        # - If a high threat probability is detected, an indicator is appended to the results.
        if self.model and self.tokenizer:
            transformer_results = self.analyze_with_transformer(text)
            if "error" not in transformer_results:
                ml_threat_prob = transformer_results.get("threat_probability", 0.0)
                # Weighted addition of ML score
                # Scale probability (0-1) to threat score points (0-10 roughly)
                # Assuming ML is more accurate, we might give it significant weight
                # However, since the default model is not fine-tuned, we keep the weight low or handle it carefully.

                # NOTE: Without a fine-tuned model, predictions from 'distilbert-base-uncased'
                # (default config) might not be meaningful for "threat" specifically.
                # Assuming the user will provide a proper model or this is a structure setup.

                # If the probability suggests a threat (>0.5), we increase the score.
                if ml_threat_prob > 0.5:
                     ml_score = (ml_threat_prob - 0.5) * 20 # Map 0.5-1.0 to 0-10 points
                     threat_score += ml_score
                     social_engineering.append(f"ML Model detected high threat probability: {ml_threat_prob:.2f}")

        
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
    
    def _detect_social_engineering(self, text: str) -> Tuple[float, List[str]]:
        """Detect social engineering patterns"""
        score = 0.0
        indicators = []
        
        for pattern, description in self.SOCIAL_ENGINEERING_PATTERNS:
            matches = re.findall(pattern, text, re.IGNORECASE)
            if matches:
                score += len(matches) * 2.0  # High weight for social engineering
                indicators.append(f"{description} ({len(matches)} occurrences)")
        
        return score, indicators
    
    def _detect_urgency(self, text: str) -> Tuple[float, List[str]]:
        """Detect urgency and time pressure tactics"""
        score = 0.0
        indicators = []
        
        for pattern, description in self.URGENCY_PATTERNS:
            matches = re.findall(pattern, text, re.IGNORECASE)
            if matches:
                score += len(matches) * 1.5
                indicators.append(f"{description} ({len(matches)} occurrences)")
        
        # Check for multiple exclamation marks (urgency indicator)
        exclamation_count = text.count('!')
        if exclamation_count > 2:
            score += exclamation_count * 0.5
            indicators.append(f"Excessive exclamation marks ({exclamation_count})")
        
        # Check for all caps words (shouting)
        caps_words = re.findall(r'\b[A-Z]{4,}\b', text)
        if len(caps_words) > 3:
            score += len(caps_words) * 0.3
            indicators.append(f"Excessive caps words ({len(caps_words)})")
        
        return score, indicators
    
    def _detect_authority_impersonation(self, text: str, sender: str) -> Tuple[float, List[str]]:
        """Detect authority impersonation attempts"""
        score = 0.0
        indicators = []
        
        sender_lower = sender.lower()
        
        for pattern, description in self.AUTHORITY_PATTERNS:
            matches = re.findall(pattern, text, re.IGNORECASE)
            if matches:
                # Check if authority claim matches sender domain
                authority_mismatch = False
                
                for match in matches:
                    # Extract sender domain
                    domain_match = re.search(r'@([\w\.-]+)', sender_lower)
                    if domain_match:
                        sender_domain = domain_match.group(1)
                        
                        # Check if claimed authority matches sender domain
                        if match.lower() not in sender_domain:
                            authority_mismatch = True
                            break
                
                if authority_mismatch:
                    score += len(matches) * 2.5  # High score for mismatch
                    indicators.append(f"{description} (domain mismatch)")
                else:
                    score += len(matches) * 0.5
                    indicators.append(f"{description}")
        
        return score, indicators
    
    def _detect_psychological_triggers(self, text: str) -> Tuple[float, List[str]]:
        """Detect psychological manipulation tactics"""
        score = 0.0
        indicators = []
        
        for pattern, description in self.PSYCHOLOGICAL_PATTERNS:
            matches = re.findall(pattern, text, re.IGNORECASE)
            if matches:
                score += len(matches) * 1.0
                indicators.append(f"{description} ({len(matches)} occurrences)")
        
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
        if not self.model or not self.tokenizer:
            return {"error": "Model not loaded"}
        
        try:
            # Tokenize and predict
            inputs = self.tokenizer(text, return_tensors="pt", truncation=True, max_length=512)
            # Move input tensors to the same device as the model
            device = next(self.model.parameters()).device
            inputs = {k: v.to(device) for k, v in inputs.items()}
            outputs = self.model(**inputs)
            predictions = torch.softmax(outputs.logits, dim=-1)
            
            # Dynamically determine which index corresponds to the 'threat' label
            id2label = getattr(self.model.config, "id2label", None)
            threat_index = None
            if id2label:
                for idx, label in id2label.items():
                    if label.strip().lower() == "threat":
            with torch.no_grad():
                outputs = self.model(**inputs)
                predictions = torch.softmax(outputs.logits, dim=-1)
            
                # Assuming binary classification where index 1 is threat
                # If the model has different labels, this logic needs adjustment
                if predictions.shape[1] >= 2:
                     threat_probability = predictions[0][1].item()
                else:
                     threat_probability = predictions[0][0].item() # Fallback for single output

                confidence = torch.max(predictions).item()

            # Return results
            return {
                "threat_probability": threat_probability,
                "confidence": confidence
            }
        except Exception as e:
            self.logger.error(f"Transformer analysis error: {e}")
            return {"error": str(e)}

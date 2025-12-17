"""
Layer 3: Media Authenticity Verification
Analyzes attachments for synthetic content and deepfakes
"""

import logging
import hashlib
from typing import List, Dict, Tuple
from dataclasses import dataclass

from .email_ingestion import EmailData


@dataclass
class MediaAnalysisResult:
    """Result of media analysis"""
    threat_score: float
    suspicious_attachments: List[str]
    file_type_warnings: List[str]
    size_anomalies: List[str]
    potential_deepfakes: List[str]
    risk_level: str


class MediaAuthenticityAnalyzer:
    """Analyzes media attachments for authenticity and threats"""

    # Dangerous file extensions
    DANGEROUS_EXTENSIONS = [
        '.exe', '.bat', '.cmd', '.com', '.pif', '.scr', '.vbs', '.js',
        '.jar', '.msi', '.dll', '.hta', '.wsf', '.ps1', '.sh', '.app'
    ]

    # Suspicious file extensions (commonly used for disguise)
    SUSPICIOUS_EXTENSIONS = [
        '.pdf.exe', '.doc.exe', '.jpg.exe', '.zip.exe',
        '.docm', '.xlsm', '.pptm', '.dotm'  # Macro-enabled Office files
    ]

    # Audio/video file extensions for deepfake detection
    MEDIA_EXTENSIONS = [
        '.mp4', '.avi', '.mov', '.wmv', '.flv', '.mkv',
        '.mp3', '.wav', '.aac', '.flac', '.ogg', '.m4a'
    ]

    def __init__(self, config):
        """
        Initialize media analyzer

        Args:
            config: AnalysisConfig object
        """
        self.config = config
        self.logger = logging.getLogger("MediaAuthenticityAnalyzer")

    def analyze(self, email_data: EmailData) -> MediaAnalysisResult:
        """
        Analyze email attachments for threats

        Args:
            email_data: Email with attachments to analyze

        Returns:
            MediaAnalysisResult
        """
        if not self.config.check_media_attachments or not email_data.attachments:
            return MediaAnalysisResult(
                threat_score=0.0,
                suspicious_attachments=[],
                file_type_warnings=[],
                size_anomalies=[],
                potential_deepfakes=[],
                risk_level="low"
            )

        threat_score = 0.0
        suspicious_attachments = []
        file_type_warnings = []
        size_anomalies = []
        potential_deepfakes = []

        for attachment in email_data.attachments:
            filename = attachment.get('filename', '')
            content_type = attachment.get('content_type', '')
            size = attachment.get('size', 0)
            data = attachment.get('data', b'')
            truncated = attachment.get('truncated', False)

            if truncated:
                size_anomalies.append(f"Attachment truncated for scanning: {filename}")

            # Check file extension
            ext_score, ext_warnings = self._check_file_extension(filename)
            threat_score += ext_score
            file_type_warnings.extend(ext_warnings)

            # Check content type mismatch
            mismatch_score, mismatch_warnings = self._check_content_type_mismatch(
                filename, content_type, data
            )
            threat_score += mismatch_score
            if mismatch_warnings:
                suspicious_attachments.append(f"{filename}: {mismatch_warnings}")

            # Check file size anomalies
            size_score, size_warning = self._check_size_anomaly(filename, size)
            threat_score += size_score
            if size_warning:
                size_anomalies.append(size_warning)

            # Check for potential deepfakes
            if self.config.deepfake_detection_enabled:
                deepfake_score, deepfake_indicators = self._check_deepfake_indicators(
                    filename, data, content_type
                )
                threat_score += deepfake_score
                potential_deepfakes.extend(deepfake_indicators)

        # Calculate risk level
        risk_level = self._calculate_risk_level(threat_score)

        self.logger.debug(
            f"Media analysis complete: {len(email_data.attachments)} attachments, "
            f"score={threat_score:.2f}, risk={risk_level}"
        )

        return MediaAnalysisResult(
            threat_score=threat_score,
            suspicious_attachments=suspicious_attachments,
            file_type_warnings=file_type_warnings,
            size_anomalies=size_anomalies,
            potential_deepfakes=potential_deepfakes,
            risk_level=risk_level
        )

    def _check_file_extension(self, filename: str) -> Tuple[float, List[str]]:
        """Check if file extension is dangerous"""
        score = 0.0
        warnings = []

        filename_lower = filename.lower()

        # Check for dangerous extensions
        for ext in self.DANGEROUS_EXTENSIONS:
            if filename_lower.endswith(ext):
                score += 5.0  # Very high score for dangerous files
                warnings.append(f"Dangerous file type: {filename}")
                break

        # Check for suspicious extensions
        for ext in self.SUSPICIOUS_EXTENSIONS:
            if ext in filename_lower:
                score += 3.0
                warnings.append(f"Suspicious file extension: {filename}")
                break

        # Check for double extensions
        parts = filename_lower.split('.')
        if len(parts) > 2:
            score += 1.5
            warnings.append(f"Multiple extensions detected: {filename}")

        return score, warnings

    def _check_content_type_mismatch(self, filename: str, content_type: str, data: bytes) -> Tuple[float, str]:
        """Check if actual file content matches declared content type"""
        if not data or len(data) < 4:
            return 0.0, ""

        # Magic bytes for common file types
        magic_bytes = {
            'pdf': b'%PDF',
            'zip': b'PK\x03\x04',
            'jpeg': b'\xff\xd8\xff',
            'png': b'\x89PNG',
            'gif': b'GIF8',
            'exe': b'MZ',
            'doc': b'\xd0\xcf\x11\xe0',
        }

        # Detect actual file type from magic bytes
        actual_type = None
        for file_type, magic in magic_bytes.items():
            if data.startswith(magic):
                actual_type = file_type
                break

        if actual_type:
            # Check if extension matches detected type
            filename_lower = filename.lower()

            # Special case for executables disguised as documents
            if actual_type == 'exe' and not filename_lower.endswith('.exe'):
                return 5.0, "Executable disguised as another file type"

            # Check for general mismatches
            expected_extensions = {
                'pdf': ['.pdf'],
                'zip': ['.zip', '.docx', '.xlsx', '.pptx'],
                'jpeg': ['.jpg', '.jpeg'],
                'png': ['.png'],
                'gif': ['.gif'],
                'doc': ['.doc', '.xls', '.ppt'],
                'exe': ['.exe', '.dll', '.com']
            }

            if actual_type in expected_extensions:
                expected_exts = expected_extensions[actual_type]
                if not any(filename_lower.endswith(ext) for ext in expected_exts):
                    return 2.0, f"File type mismatch: {filename}"

        return 0.0, ""

    def _check_size_anomaly(self, filename: str, size: int) -> Tuple[float, str]:
        """Check for unusual file sizes"""
        score = 0.0
        warning = ""

        # Very large attachments (potential data exfiltration)
        if size > 25 * 1024 * 1024:  # 25MB
            score += 1.5
            warning = f"Unusually large attachment: {filename} ({size / (1024*1024):.1f}MB)"

        # Suspiciously small media files
        filename_lower = filename.lower()
        if any(filename_lower.endswith(ext) for ext in self.MEDIA_EXTENSIONS):
            if size < 1024:  # Less than 1KB
                score += 1.0
                warning = f"Suspiciously small media file: {filename} ({size} bytes)"

        return score, warning

    def _check_deepfake_indicators(self, filename: str, data: bytes, content_type: str) -> Tuple[float, List[str]]:
        """
        Check for potential deepfake indicators

        Note: This is a placeholder for more sophisticated deepfake detection
        Real deepfake detection would require ML models and is computationally expensive
        """
        score = 0.0
        indicators = []

        filename_lower = filename.lower()

        # Check if file is audio/video
        is_media = any(filename_lower.endswith(ext) for ext in self.MEDIA_EXTENSIONS)

        if not is_media:
            return score, indicators

        # Basic heuristics (in production, use specialized deepfake detection models)

        # Check for very small video files (often low quality deepfakes)
        if filename_lower.endswith(('.mp4', '.avi', '.mov')):
            size = len(data)
            if size < 100 * 1024:  # Less than 100KB
                score += 0.5
                indicators.append(f"Suspicious video size: {filename}")

        # In a real implementation, you would:
        # 1. Extract frames from video
        # 2. Analyze for facial inconsistencies
        # 3. Check audio-visual synchronization
        # 4. Look for compression artifacts typical of deepfakes
        # 5. Use specialized deepfake detection models

        if self.config.deepfake_detection_enabled:
            deepfake_probability = self._run_deepfake_model(filename, data, content_type)
            if deepfake_probability > 0.7:
                score += 3.0
                indicators.append(f"High deepfake probability: {filename} ({deepfake_probability:.2f})")
            elif deepfake_probability > 0.4:
                score += 1.0
                indicators.append(f"Possible deepfake content: {filename} ({deepfake_probability:.2f})")

        return score, indicators

    def _run_deepfake_model(self, filename: str, data: bytes, content_type: str) -> float:
        """
        Run deepfake detection model based on configured provider

        Args:
            filename: Name of the file
            data: File data
            content_type: MIME type

        Returns:
            Probability of deepfake (0.0 to 1.0)
        """
        provider = self.config.deepfake_provider

        if provider == "simulator":
            return self._scan_simulator(filename, data)
        elif provider == "microsoft":
            return self._scan_microsoft(data)
        elif provider == "sensity":
            return self._scan_sensity(data)
        elif provider == "faceforensics":
            return self._scan_faceforensics(data)
        else:
            self.logger.warning(f"Unknown deepfake provider: {provider}")
            return 0.0

    def _scan_simulator(self, filename: str, data: bytes) -> float:
        """
        Simulate deepfake detection for testing purposes
        """
        # Simulate high probability for specific filenames
        if "deepfake" in filename.lower() or "synthetic" in filename.lower():
            self.logger.info(f"Simulator: Detected synthetic content in {filename}")
            return 0.85

        # Simulate medium probability
        if "suspicious" in filename.lower():
            return 0.5

        return 0.0

    def _scan_microsoft(self, data: bytes) -> float:
        """
        Placeholder for Microsoft Video Authenticator integration
        """
        if not self.config.deepfake_api_key:
            self.logger.warning("Microsoft Video Authenticator API key not configured")
            return 0.0

        # TODO: Implement actual API call
        self.logger.info("Microsoft Video Authenticator scan requested (not implemented)")
        return 0.0

    def _scan_sensity(self, data: bytes) -> float:
        """
        Placeholder for Sensity AI integration
        """
        if not self.config.deepfake_api_key:
            self.logger.warning("Sensity AI API key not configured")
            return 0.0

        # TODO: Implement actual API call
        self.logger.info("Sensity AI scan requested (not implemented)")
        return 0.0

    def _scan_faceforensics(self, data: bytes) -> float:
        """
        Placeholder for FaceForensics++ model integration
        """
        if not self.config.deepfake_model_path:
            self.logger.warning("FaceForensics++ model path not configured")
            return 0.0

        # TODO: Load model and run inference
        self.logger.info("FaceForensics++ model scan requested (not implemented)")
        return 0.0

    def _calculate_risk_level(self, score: float) -> str:
        """Calculate risk level based on media threat score"""
        if score >= 5.0:
            return "high"
        elif score >= 2.0:
            return "medium"
        else:
            return "low"

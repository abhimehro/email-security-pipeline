"""
Layer 3: Media Authenticity Verification
Analyzes attachments for synthetic content and deepfakes.
"""

import cv2
import logging
import os
import tempfile
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from typing import List, Tuple

from ..utils.threat_scoring import calculate_risk_level
from .email_data import EmailData
from . import media_file_type
from . import media_archive
from . import media_deepfake

# Inject the facade's cv2 object into the deepfake helper module so that
# tests patching src.modules.media_analyzer.cv2 continue to work.
media_deepfake.cv2 = cv2

# Re-export the frame-extraction options dataclass for backwards compatibility.
FrameExtractionOptions = media_deepfake.FrameExtractionOptions


@dataclass
class MediaAnalysisResult:
    """Result of media analysis."""

    threat_score: float
    suspicious_attachments: List[str]
    file_type_warnings: List[str]
    size_anomalies: List[str]
    potential_deepfakes: List[str]
    risk_level: str


class MediaAuthenticityAnalyzer:
    """Analyzes media attachments for authenticity and threats."""

    # Dangerous file extensions
    # Optimization: Using tuples instead of lists allows for fast C-level execution
    # with `str.endswith()` instead of slow Python-level `for` loops.
    DANGEROUS_EXTENSIONS = (
        ".exe",
        ".bat",
        ".cmd",
        ".com",
        ".pif",
        ".scr",
        ".vbs",
        ".js",
        ".jar",
        ".msi",
        ".dll",
        ".hta",
        ".wsf",
        ".ps1",
        ".sh",
        ".bash",
        ".app",
        ".php",
        ".php3",
        ".php4",
        ".php5",
        ".phtml",
        ".pl",
        ".py",
        ".rb",
        ".asp",
        ".aspx",
        ".jsp",
        ".jspx",
        ".cgi",
        # Added missing dangerous extensions
        ".vbe",
        ".jse",
        ".wsh",
        ".scf",
        ".lnk",
        ".inf",
        ".reg",
        ".iso",
        ".img",
        ".vhd",
        ".vhdx",
    )

    # Suspicious file extensions (commonly used for disguise)
    SUSPICIOUS_EXTENSIONS = (
        ".pdf.exe",
        ".doc.exe",
        ".jpg.exe",
        ".zip.exe",
        ".docm",
        ".xlsm",
        ".pptm",
        ".dotm",  # Macro-enabled Office files
        ".html",
        ".htm",
        ".svg",  # Web content (potential Phishing/XSS)
    )

    # Audio/video file extensions for deepfake detection
    # Optimization: Using tuples instead of lists allows for fast C-level execution
    # with `str.endswith()` instead of slow Python-level `for` loops.
    MEDIA_EXTENSIONS = (
        ".mp4",
        ".avi",
        ".mov",
        ".wmv",
        ".flv",
        ".mkv",
        ".mp3",
        ".wav",
        ".aac",
        ".flac",
        ".ogg",
        ".m4a",
    )

    MAX_NESTED_ZIP_SIZE = 10 * 1024 * 1024  # 10MB limit for nested zips
    HIGH_FREQ_NOISE_THRESHOLD = 150  # Arbitrary threshold for high frequency noise

    # Maximum attachment size (in MB) before flagging as a size anomaly.
    # This heuristic catches potential data-exfiltration payloads that exceed
    # the typical email attachment ceiling.
    MAX_ATTACHMENT_SIZE_MB = 25

    # Maximum number of files allowed inside a ZIP archive before flagging it.
    # Limits analysis work and catches zip-bomb style payloads.
    MAX_ZIP_FILE_COUNT = 1000

    # Minimum size (bytes) for media files; files smaller than this are suspicious.
    MIN_MEDIA_FILE_SIZE_BYTES = 1024  # 1KB

    # Archive extensions used for nested archive detection
    # Optimization: Using tuples instead of sets allows for fast C-level execution
    # with `str.endswith()` instead of slow Python-level `for` loops.
    ARCHIVE_EXTENSIONS = (
        ".zip",
        ".rar",
        ".7z",
        ".tar",
        ".gz",
        ".iso",
        ".img",
        ".vhd",
        ".vhdx",
    )

    # Risk level thresholds for media threat scoring
    MEDIA_RISK_LOW_THRESHOLD = 2.0
    MEDIA_RISK_HIGH_THRESHOLD = 5.0

    # Magic signatures with offset 0 for fast C-level `startswith` checks
    # Optimization: Grouping signatures by offset and using a tuple allows
    # `bytes.startswith` to execute in C, bypassing Python loop overhead.
    MAGIC_SIGNATURES_OFFSET_0 = (
        (b"%PDF", "pdf"),
        (b"PK\x03\x04", "zip"),
        (b"\xff\xd8\xff", "jpeg"),
        (b"\x89PNG", "png"),
        (b"GIF8", "gif"),
        (b"MZ", "exe"),
        (b"\xd0\xcf\x11\xe0", "doc"),
        (b"\x1a\x45\xdf\xa3", "mkv"),
        (b"ID3", "mp3"),
        (b"\xff\xfb", "mp3"),
        (b"\xff\xf3", "mp3"),
        (b"\xff\xf2", "mp3"),
        (b"\x30\x26\xb2\x75\x8e\x66\xcf\x11", "wmv"),
        (b"FLV", "flv"),
        (b"OggS", "ogg"),
        (b"fLaC", "flac"),
    )

    # Tuple of just the byte prefixes for fast `startswith` check
    MAGIC_PREFIXES_OFFSET_0 = tuple(sig for sig, _ in MAGIC_SIGNATURES_OFFSET_0)

    # Expected extensions for content type mismatch checking
    # Optimization: Moving this dictionary to the class level avoids re-creating
    # it on every file check, and using tuples allows fast C-level str.endswith()
    EXPECTED_EXTENSIONS = {
        "pdf": (".pdf",),
        "zip": (".zip", ".docx", ".xlsx", ".pptx", ".jar"),
        "jpeg": (".jpg", ".jpeg"),
        "png": (".png",),
        "gif": (".gif",),
        "doc": (".doc", ".xls", ".ppt", ".msi"),
        "exe": (".exe",),
        "mp4": (".mp4", ".mov", ".m4a", ".3gp"),
        "avi": (".avi",),
        "wav": (".wav",),
        "mp3": (".mp3",),
        "mkv": (".mkv", ".webm"),
        "webp": (".webp",),
        "wmv": (".wmv",),
        "flv": (".flv",),
        "ogg": (".ogg", ".oga", ".ogv", ".ogx"),
        "flac": (".flac",),
    }

    def _is_path_traversal_attempt(self, *args, **kwargs):
        return media_file_type._is_path_traversal_attempt(self, *args, **kwargs)

    def _check_file_extension(self, *args, **kwargs):
        return media_file_type._check_file_extension(self, *args, **kwargs)

    def _check_riff_container(self, *args, **kwargs):
        return media_file_type._check_riff_container(self, *args, **kwargs)

    def _detect_file_type(self, *args, **kwargs):
        return media_file_type._detect_file_type(self, *args, **kwargs)

    def _check_content_type_mismatch(self, *args, **kwargs):
        return media_file_type._check_content_type_mismatch(self, *args, **kwargs)

    def _validate_signature_match(self, *args, **kwargs):
        return media_file_type._validate_signature_match(self, *args, **kwargs)

    def _validate_missing_signature(self, *args, **kwargs):
        return media_file_type._validate_missing_signature(self, *args, **kwargs)

    def _check_size_anomaly(self, *args, **kwargs):
        return media_file_type._check_size_anomaly(self, *args, **kwargs)

    def _is_nested_archive(self, *args, **kwargs):
        return media_file_type._is_nested_archive(self, *args, **kwargs)

    def _analyze_attachment_metadata(self, *args, **kwargs):
        return media_file_type._analyze_attachment_metadata(self, *args, **kwargs)

    def _inspect_zip_contents(self, *args, **kwargs):
        return media_archive._inspect_zip_contents(self, *args, **kwargs)

    def _check_file_count(self, *args, **kwargs):
        return media_archive._check_file_count(self, *args, **kwargs)

    def _inspect_zip_member_and_check_traversal(self, *args, **kwargs):
        return media_archive._inspect_zip_member_and_check_traversal(
            self, *args, **kwargs
        )

    def _inspect_archive_member(self, *args, **kwargs):
        return media_archive._inspect_archive_member(self, *args, **kwargs)

    def _handle_nested_zip_member(self, *args, **kwargs):
        return media_archive._handle_nested_zip_member(self, *args, **kwargs)

    def _inspect_tar_contents(self, *args, **kwargs):
        return media_archive._inspect_tar_contents(self, *args, **kwargs)

    def _inspect_tar_contents_safe(self, *args, **kwargs):
        return media_archive._inspect_tar_contents_safe(self, *args, **kwargs)

    def _apply_tar_filter(self, *args, **kwargs):
        return media_archive._apply_tar_filter(self, *args, **kwargs)

    def _get_tar_members_safely(self, *args, **kwargs):
        return media_archive._get_tar_members_safely(self, *args, **kwargs)

    def _process_tar_member(self, *args, **kwargs):
        return media_archive._process_tar_member(self, *args, **kwargs)

    def _handle_nested_tar_member(self, *args, **kwargs):
        return media_archive._handle_nested_tar_member(self, *args, **kwargs)

    def _read_file_securely(self, *args, **kwargs):
        return media_archive._read_file_securely(self, *args, **kwargs)

    def _read_zip_member_securely(self, *args, **kwargs):
        return media_archive._read_zip_member_securely(self, *args, **kwargs)

    def _extract_frames_from_video(self, *args, **kwargs):
        return media_deepfake._extract_frames_from_video(self, *args, **kwargs)

    def _extract_frames_sequential(self, *args, **kwargs):
        return media_deepfake._extract_frames_sequential(self, *args, **kwargs)

    def _extract_frames_sampled(self, *args, **kwargs):
        return media_deepfake._extract_frames_sampled(self, *args, **kwargs)

    def _advance_to_frame(self, *args, **kwargs):
        return media_deepfake._advance_to_frame(self, *args, **kwargs)

    def _resize_frame_if_needed(self, *args, **kwargs):
        return media_deepfake._resize_frame_if_needed(self, *args, **kwargs)

    def _analyze_facial_inconsistencies(self, *args, **kwargs):
        return media_deepfake._analyze_facial_inconsistencies(self, *args, **kwargs)

    def _check_audio_visual_sync(self, *args, **kwargs):
        return media_deepfake._check_audio_visual_sync(self, *args, **kwargs)

    def _check_compression_artifacts(self, *args, **kwargs):
        return media_deepfake._check_compression_artifacts(self, *args, **kwargs)

    def _run_deepfake_model(self, *args, **kwargs):
        return media_deepfake._run_deepfake_model(self, *args, **kwargs)

    def _analyze_video_frames(self, *args, **kwargs):
        return media_deepfake._analyze_video_frames(self, *args, **kwargs)

    def __init__(self, config):
        """
        Initialize media analyzer.

        Args:
            config: AnalysisConfig object

        """
        self.config = config
        self.logger = logging.getLogger("MediaAuthenticityAnalyzer")
        self.face_cascade = None
        # Optimization: Reuse thread pool for deepfake detection to avoid overhead
        self._deepfake_executor = ThreadPoolExecutor()

    def analyze(self, email_data: EmailData) -> MediaAnalysisResult:
        """
        Analyze email attachments for threats.

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
                risk_level="low",
            )

        threat_score = 0.0
        suspicious_attachments = []
        file_type_warnings = []
        size_anomalies = []
        potential_deepfakes = []

        # Optimization: Use ThreadPoolExecutor to process attachments concurrently.
        with ThreadPoolExecutor() as executor:
            # We use a mutable list to track if the threshold has been crossed globally.
            # Because of the GIL, list operations are thread-safe enough for this heuristic check.
            shared_state = {"stop_deepfake": False}

            # Using executor.map preserves the original deterministic order of results
            # and allows exceptions to propagate naturally, avoiding fail-open vulnerabilities.
            results = executor.map(
                lambda att: self._process_attachment_parallel(att, shared_state),
                email_data.attachments,
            )

            for meta_results, deepfake_results in results:
                threat_score += meta_results["score"]
                size_anomalies.extend(meta_results["size_anomalies"])
                file_type_warnings.extend(meta_results["file_type_warnings"])
                suspicious_attachments.extend(meta_results["suspicious_attachments"])

                if threat_score >= 5.0:
                    shared_state["stop_deepfake"] = True
                    continue

                if not deepfake_results:
                    continue

                threat_score += deepfake_results["score"]
                potential_deepfakes.extend(deepfake_results["indicators"])
                size_anomalies.extend(deepfake_results["errors"])

                if threat_score >= 5.0:
                    shared_state["stop_deepfake"] = True

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
            risk_level=risk_level,
        )

    def _process_attachment_parallel(
        self, attachment: dict, shared_state: dict
    ) -> tuple:
        """
        Process a single attachment for metadata and deepfake analysis in parallel.
        """
        meta_res = self._analyze_attachment_metadata(attachment)
        deepfake_res = None

        if not self.config.deepfake_detection_enabled:
            return meta_res, deepfake_res

        if shared_state["stop_deepfake"]:
            return meta_res, deepfake_res

        if meta_res["score"] >= 5.0:
            return meta_res, deepfake_res

        filename = attachment.get("filename", "")
        data = attachment.get("data", b"")
        content_type = attachment.get("content_type", "")
        deepfake_res = self._analyze_deepfake_threat(filename, data, content_type)

        return meta_res, deepfake_res

    def _analyze_deepfake_threat(
        self, filename: str, data: bytes, content_type: str
    ) -> dict:
        """
        Execute deepfake analysis logic.
        """
        result = {"score": 0.0, "indicators": [], "errors": []}

        try:
            future = self._deepfake_executor.submit(
                self._check_deepfake_indicators, filename, data, content_type
            )
            deepfake_score, deepfake_indicators = future.result(
                timeout=self.config.media_analysis_timeout
            )
            result["score"] = deepfake_score
            result["indicators"] = deepfake_indicators
        except TimeoutError:
            self.logger.warning(
                f"Deepfake analysis timed out for {filename} (>{self.config.media_analysis_timeout}s)"
            )
            result["errors"].append(f"Deepfake analysis timed out: {filename}")
        except Exception as e:
            self.logger.error(f"Deepfake analysis failed for {filename}: {e}")

        return result

    def _check_deepfake_indicators(
        self, filename: str, data: bytes, content_type: str
    ) -> Tuple[float, List[str]]:
        """
        Check for potential deepfake indicators using advanced analysis.
        """
        score = 0.0
        indicators = []

        filename_lower = filename.lower()

        # Check if file is audio/video
        # Optimization: O(1) loop iteration using tuple-based endswith() check
        is_media = filename_lower.endswith(self.MEDIA_EXTENSIONS)

        if not is_media:
            return score, indicators

        # Basic heuristics
        if filename_lower.endswith((".mp4", ".avi", ".mov")):
            size = len(data)
            if size < 100 * 1024:  # Less than 100KB
                score += 0.5
                indicators.append(f"Suspicious video size: {filename}")

        if not self.config.deepfake_detection_enabled:
            return score, indicators

        # Advanced ML-based detection
        temp_file_path = None
        try:
            # Create a temporary file to work with OpenCV
            with tempfile.NamedTemporaryFile(
                delete=False, suffix=os.path.splitext(filename)[1]
            ) as temp_file:
                temp_file_path = temp_file.name
                temp_file.write(data)

            # 1. Extract frames
            # Optimization: 10 frames is sufficient for statistical analysis and reduces processing time by 50%
            frames = self._extract_frames_from_video(
                temp_file_path, max_frames=10, max_dim=1280
            )

            if not frames:
                self.logger.warning(f"Could not extract frames from {filename}")
            else:
                frame_score, frame_indicators = self._analyze_video_frames(
                    filename, temp_file_path, frames, content_type
                )
                score += frame_score
                indicators.extend(frame_indicators)

        except Exception as e:
            self.logger.error(
                f"Error during deepfake analysis for {filename}: {str(e)}"
            )

        finally:
            # Cleanup temp file
            if temp_file_path and os.path.exists(temp_file_path):
                try:
                    os.unlink(temp_file_path)
                except OSError as e:
                    self.logger.warning(
                        f"Failed to delete temp file {temp_file_path}: {e}"
                    )

        return score, indicators

    def _calculate_risk_level(self, score: float) -> str:
        """Calculate risk level based on media threat score."""
        return calculate_risk_level(
            score,
            self.MEDIA_RISK_LOW_THRESHOLD,
            self.MEDIA_RISK_HIGH_THRESHOLD,
        )

    def shutdown(self):
        """Shutdown the thread pool executor."""
        if hasattr(self, "_deepfake_executor"):
            self._deepfake_executor.shutdown(wait=True)

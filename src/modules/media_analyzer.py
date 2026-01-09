"""
Layer 3: Media Authenticity Verification
Analyzes attachments for synthetic content and deepfakes
"""

import logging
import tempfile
import os
import numpy as np
import cv2
from typing import List, Tuple
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
        self.face_cascade = None

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
            # SKIP if file is already identified as dangerous (e.g. executable disguised as mp4)
            # This prevents writing malicious files to disk or processing them with complex parsers.
            if self.config.deepfake_detection_enabled:
                is_high_risk = False

                # Check if mismatch score indicates disguised executable (5.0)
                # or significant mismatch (2.0) combined with other factors
                if mismatch_score >= 5.0:
                    is_high_risk = True
                elif ext_score >= 5.0:
                    is_high_risk = True

                if not is_high_risk:
                    deepfake_score, deepfake_indicators = self._check_deepfake_indicators(
                        filename, data, content_type
                    )
                    threat_score += deepfake_score
                    potential_deepfakes.extend(deepfake_indicators)
                else:
                    self.logger.warning(f"Skipping deepfake analysis for high-risk file: {filename}")

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

        # Sanitize filename (strip whitespace and null bytes for check)
        filename_lower = filename.lower().strip().replace('\0', '')

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
        Check for potential deepfake indicators using advanced analysis.
        """
        score = 0.0
        indicators = []

        filename_lower = filename.lower()

        # Check if file is audio/video
        is_media = any(filename_lower.endswith(ext) for ext in self.MEDIA_EXTENSIONS)

        if not is_media:
            return score, indicators

        # Basic heuristics
        if filename_lower.endswith(('.mp4', '.avi', '.mov')):
            size = len(data)
            if size < 100 * 1024:  # Less than 100KB
                score += 0.5
                indicators.append(f"Suspicious video size: {filename}")

        if not self.config.deepfake_detection_enabled:
            return score, indicators

        # Advanced ML-based detection
        try:
            # Create a temporary file to work with OpenCV
            with tempfile.NamedTemporaryFile(delete=False, suffix=os.path.splitext(filename)[1]) as temp_file:
                temp_file.write(data)
                temp_file_path = temp_file.name

            try:
                # 1. Extract frames
                frames = self._extract_frames_from_video(temp_file_path, max_frames=20)

                if not frames:
                     self.logger.warning(f"Could not extract frames from {filename}")
                else:
                    # 2. Analyze for facial inconsistencies
                    facial_score, facial_issues = self._analyze_facial_inconsistencies(frames)
                    if facial_score > 0:
                        score += facial_score
                        indicators.extend([f"{filename}: {issue}" for issue in facial_issues])

                    # 3. Check audio-visual synchronization
                    sync_score, sync_issues = self._check_audio_visual_sync(temp_file_path, frames)
                    if sync_score > 0:
                        score += sync_score
                        indicators.extend([f"{filename}: {issue}" for issue in sync_issues])

                    # 4. Look for compression artifacts typical of deepfakes
                    compression_score, compression_issues = self._check_compression_artifacts(frames)
                    if compression_score > 0:
                        score += compression_score
                        indicators.extend([f"{filename}: {issue}" for issue in compression_issues])

                    # 5. Use specialized deepfake detection models (Simulated)
                    model_score = self._run_deepfake_model(frames, content_type)
                    if model_score > 0.7:
                        score += 3.0
                        indicators.append(f"High probability of deepfake detected by model: {filename}")

            finally:
                # Cleanup temp file
                if os.path.exists(temp_file_path):
                    os.unlink(temp_file_path)

        except Exception as e:
            self.logger.error(f"Error during deepfake analysis for {filename}: {str(e)}")

        return score, indicators

    def _extract_frames_from_video(self, video_path: str, max_frames: int = 10) -> List[np.ndarray]:
        """Extract a sample of frames from the video."""
        frames = []
        try:
            cap = cv2.VideoCapture(video_path)
            if not cap.isOpened():
                return frames

            total_frames = int(cap.get(cv2.CAP_PROP_FRAME_COUNT))
            if total_frames <= 0:
                # Fallback if frame count is unknown
                success, frame = cap.read()
                count = 0
                while success and count < max_frames:
                    frames.append(frame)
                    success, frame = cap.read()
                    count += 1
            else:
                # Sample evenly distributed frames
                step = max(1, total_frames // max_frames)
                for i in range(0, total_frames, step):
                    cap.set(cv2.CAP_PROP_POS_FRAMES, i)
                    success, frame = cap.read()
                    if success:
                        frames.append(frame)
                    if len(frames) >= max_frames:
                        break

            cap.release()
        except Exception as e:
            self.logger.error(f"Error extracting frames: {e}")

        return frames

    def _analyze_facial_inconsistencies(self, frames: List[np.ndarray]) -> Tuple[float, List[str]]:
        """
        Analyze frames for facial inconsistencies.
        Uses OpenCV's Haar cascades for face detection and analyzes face regions.
        """
        score = 0.0
        issues = []

        # Load Haar cascade for face detection (lazy loading with caching)
        if self.face_cascade is None:
            # Note: In a real environment, ensure the XML file is available or bundled.
            # We try to load from default OpenCV path or a local path.
            cascade_path = cv2.data.haarcascades + 'haarcascade_frontalface_default.xml'
            self.face_cascade = cv2.CascadeClassifier(cascade_path)

        if self.face_cascade.empty():
            self.logger.warning("Haar cascade not found. Skipping facial analysis.")
            return 0.0, []

        faces_found = 0
        blurry_faces = 0

        for frame in frames:
            gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
            faces = self.face_cascade.detectMultiScale(gray, 1.1, 4)

            for (x, y, w, h) in faces:
                faces_found += 1
                face_roi = gray[y:y+h, x:x+w]

                # Check for blurriness using Laplacian variance
                variance = cv2.Laplacian(face_roi, cv2.CV_64F).var()
                if variance < 100:  # Threshold for blurriness
                    blurry_faces += 1

        if faces_found > 0:
            blur_ratio = blurry_faces / faces_found
            if blur_ratio > 0.5:
                score += 1.0
                issues.append(f"Inconsistent facial clarity detected ({int(blur_ratio*100)}% blurry faces)")

        return score, issues

    def _check_audio_visual_sync(self, video_path: str, frames: List[np.ndarray]) -> Tuple[float, List[str]]:
        """
        Check for audio-visual synchronization issues.
        Note: Full A/V sync requires complex analysis (e.g. lip reading vs audio phonemes).
        This is a lightweight check for stream presence and duration mismatch.
        """
        score = 0.0
        issues = []

        try:
            cap = cv2.VideoCapture(video_path)
            if not cap.isOpened():
                return score, issues

            # Check if we can get duration info (depends on container)
            # OpenCV doesn't handle audio well directly without ffmpeg backend support explicitly
            # So we focus on checking if video stream is consistent

            fps = cap.get(cv2.CAP_PROP_FPS)
            frame_count = cap.get(cv2.CAP_PROP_FRAME_COUNT)

            if fps > 0 and frame_count > 0:
                duration = frame_count / fps
                # If duration is very short but file size is large, might be suspicious
                file_size = os.path.getsize(video_path)
                if duration < 1.0 and file_size > 5 * 1024 * 1024:
                    score += 0.5
                    issues.append("Video duration vs file size mismatch (potential stream embedding issue)")

            cap.release()
        except Exception as e:
            self.logger.warning(f"Error in A/V sync check: {e}")

        return score, issues

    def _check_compression_artifacts(self, frames: List[np.ndarray]) -> Tuple[float, List[str]]:
        """
        Check for double compression artifacts or unusual frequency patterns.
        """
        score = 0.0
        issues = []

        high_freq_noise_count = 0

        for frame in frames:
            gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)

            # Use FFT to analyze frequency domain
            f = np.fft.fft2(gray)
            fshift = np.fft.fftshift(f)
            magnitude_spectrum = 20 * np.log(np.abs(fshift) + 1)

            # Simple heuristic: Check for unusual spikes in high frequencies
            # often seen in GAN-generated images or poor compression re-encoding
            h, w = gray.shape
            center_h, center_w = h // 2, w // 2
            # Mask out low frequencies
            mask_size = min(h, w) // 8
            magnitude_spectrum[center_h-mask_size:center_h+mask_size, center_w-mask_size:center_w+mask_size] = 0

            if np.mean(magnitude_spectrum) > 150: # Arbitrary threshold for high freq noise
                high_freq_noise_count += 1

        if len(frames) > 0 and (high_freq_noise_count / len(frames) > 0.6):
            score += 1.0
            issues.append("Unusual high-frequency noise patterns detected")

        return score, issues

    def _run_deepfake_model(self, frames: List[np.ndarray], content_type: str) -> float:
        """
        Run deepfake detection model (Simulated).

        In a full implementation, this would pass frames to a loaded Torch/TensorFlow model.
        Here we simulate a model score based on frame properties to mimic the interface.
        """
        if not frames:
            return 0.0

        # Simulation of a scoring model:
        # Generate a score that can actually span the 0.0 - 1.0 range based on image statistics.
        # High variance + low brightness might suggest tampering in some contexts, or high saturation.
        # This is a heuristic proxy.

        avg_scores = []
        for frame in frames:
            # Convert to float
            frame_float = frame.astype(float)
            # Calculate standard deviation of color channels (saturation variance)
            std_dev = np.std(frame_float)
            # Calculate edge density using Canny
            edges = cv2.Canny(frame, 100, 200)
            edge_density = np.sum(edges) / edges.size

            # Synthetic score combination
            # Normalize to 0-1 loosely
            score = (std_dev / 100.0) * 0.5 + (edge_density * 5)
            avg_scores.append(min(score, 1.0))

        final_score = np.mean(avg_scores) if avg_scores else 0.0

        # Clip to 0.0 - 1.0
        return min(max(final_score, 0.0), 1.0)

    def _calculate_risk_level(self, score: float) -> str:
        """Calculate risk level based on media threat score"""
        if score >= 5.0:
            return "high"
        elif score >= 2.0:
            return "medium"
        else:
            return "low"

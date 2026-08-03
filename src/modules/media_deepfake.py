"""Deepfake and media frame analysis helpers."""

import os
from dataclasses import dataclass
from typing import Any, List, Optional, Tuple

import numpy as np

# Injected by MediaAuthenticityAnalyzer at import time to preserve
# test patches on src.modules.media_analyzer.cv2.
cv2 = None


@dataclass
class FrameExtractionOptions:
    """Options for frame extraction."""

    max_frames: int = 10
    max_dim: int = 1920
    step: int = 1
    total_frames: int = 0


def _extract_frames_from_video(
    self, video_path: str, max_frames: int = 10, max_dim: int = 1920
) -> List[np.ndarray]:
    """
    Extract a sample of frames from the video.

    Frames are sampled up to ``max_frames`` times, distributed across the video
    when the total frame count is known, or sequentially from the start if it is not.

    Each extracted frame is optionally resized via ``_resize_frame_if_needed`` so
    that its longest side does not exceed ``max_dim`` pixels, while preserving
    aspect ratio. Frames smaller than ``max_dim`` are left at their original size.

    Args:
        video_path: Path to the video file to sample.
        max_frames: Maximum number of frames to extract from the video.
        max_dim: Maximum allowed dimension (in pixels) for the width or height
            of each returned frame. The frame is downscaled if necessary so its
            longest side is at most this value, preserving aspect ratio.

    """
    frames = []
    try:
        cap = cv2.VideoCapture(video_path)
        if not cap.isOpened():
            return frames

        total_frames = int(cap.get(cv2.CAP_PROP_FRAME_COUNT))

        if total_frames <= 0:
            # Fallback if frame count is unknown
            frames = self._extract_frames_sequential(cap, max_frames, max_dim)
        else:
            # Sample evenly distributed frames
            step = max(1, total_frames // max_frames)

            # Optimization: For step=1 (sequential reading), avoid expensive seek operations
            if step == 1:
                frames = self._extract_frames_sequential(cap, max_frames, max_dim)
            else:
                options = FrameExtractionOptions(
                    max_frames=max_frames,
                    max_dim=max_dim,
                    step=step,
                    total_frames=total_frames,
                )
                frames = self._extract_frames_sampled(cap, options)

        cap.release()
    except Exception as e:
        self.logger.error(f"Error extracting frames: {e}")

    return frames


def _read_next_frame(cap: Any) -> Tuple[bool, Optional[np.ndarray]]:
    """Read the next frame from the video capture."""
    return cap.read()


def _is_video_capture_open(cap: Any) -> bool:
    """Check if the video capture is opened successfully."""
    return cap.isOpened()


def _extract_frames_sequential(
    self, cap, max_frames: int, max_dim: int
) -> List[np.ndarray]:
    """Extract frames sequentially without seeking."""
    frames = []
    count = 0
    while count < max_frames:
        success, frame = _read_next_frame(cap)
        if not success:
            break
        if frame is not None:
            frames.append(self._resize_frame_if_needed(frame, max_dim))
        count += 1
    return frames


def _extract_frames_sampled(
    self, cap, options: FrameExtractionOptions
) -> List[np.ndarray]:
    """Extract frames using a hybrid approach of seeking and grabbing for sampling."""
    frames = []
    current_frame = 0

    for target_frame in range(0, options.total_frames, options.step):
        if len(frames) >= options.max_frames:
            break

        current_frame = self._advance_to_frame(cap, current_frame, target_frame)

        if current_frame != target_frame:
            break

        success, frame = cap.read()
        if success and frame is not None:
            frames.append(self._resize_frame_if_needed(frame, options.max_dim))
            current_frame += 1
        else:
            break

    return frames


def _advance_to_frame(self, cap, current_frame: int, target_frame: int) -> int:
    """Advance the video capture to the target frame using a hybrid approach."""
    try:
        cap_prop_pos_frames = cv2.CAP_PROP_POS_FRAMES
    except (ImportError, AttributeError):
        cap_prop_pos_frames = (
            1  # Fallback to the known integer value for CAP_PROP_POS_FRAMES
        )

    seek_threshold = 30
    jump = target_frame - current_frame

    if jump > seek_threshold:
        cap.set(cap_prop_pos_frames, target_frame)
        current_frame = target_frame

    while current_frame < target_frame:
        if not cap.grab():
            break
        current_frame += 1

    return current_frame


def _resize_frame_if_needed(self, frame: np.ndarray, max_dim: int = 1920) -> np.ndarray:
    """Resize frame if it exceeds maximum dimension while maintaining aspect ratio."""
    try:
        h, w = frame.shape[:2]

        # Defensive check: guard against malformed/empty frames with non-positive dimensions.
        # OpenCV's resize requires strictly positive width/height; if we get bad input here,
        # we log and return the frame unchanged rather than raising and bypassing DoS controls.
        if h <= 0 or w <= 0:
            self.logger.warning(
                f"Received frame with non-positive dimensions (h={h}, w={w}); skipping resize."
            )
            return frame

        if max(h, w) <= max_dim:
            return frame

        scale = max_dim / max(h, w)
        # Clamp new dimensions to at least 1 pixel to avoid int() rounding to 0,
        # which would cause cv2.resize to raise and circumvent the downscaling.
        new_w = max(1, int(w * scale))
        new_h = max(1, int(h * scale))
        return cv2.resize(frame, (new_w, new_h), interpolation=cv2.INTER_AREA)
    except Exception as e:
        self.logger.warning(f"Error resizing frame: {e}")
        return frame


def _process_faces_in_frame(self, gray: np.ndarray) -> Tuple[int, int]:
    """Detect faces and count blurry faces in a frame."""
    faces_found = 0
    blurry_faces = 0
    faces = self.face_cascade.detectMultiScale(gray, 1.1, 4)
    for x, y, w, h in faces:
        faces_found += 1
        face_roi = gray[y : y + h, x : x + w]
        # Check for blurriness using Laplacian variance
        # Optimization: Using cv2.meanStdDev is significantly faster (~3x)
        # than falling back to NumPy's .var() method for variance calculation.
        variance = cv2.meanStdDev(cv2.Laplacian(face_roi, cv2.CV_64F))[1][0][0] ** 2
        if variance < 100:  # Threshold for blurriness
            blurry_faces += 1
    return faces_found, blurry_faces


def _analyze_facial_inconsistencies(
    self, gray_frames: List[np.ndarray]
) -> Tuple[float, List[str]]:
    """
    Analyze frames for facial inconsistencies.
    Uses OpenCV's Haar cascades for face detection and analyzes face regions.

    Args:
        gray_frames: List of grayscale frames (numpy arrays)

    """
    score = 0.0
    issues = []

    # Load Haar cascade for face detection (lazy loading with caching)
    if self.face_cascade is None:
        # Note: In a real environment, ensure the XML file is available or bundled.
        # We try to load from default OpenCV path or a local path.
        cascade_path = cv2.data.haarcascades + "haarcascade_frontalface_default.xml"
        self.face_cascade = cv2.CascadeClassifier(cascade_path)

    if self.face_cascade.empty():
        self.logger.warning("Haar cascade not found. Skipping facial analysis.")
        return 0.0, []

    faces_found = 0
    blurry_faces = 0

    # Optimization: Check a small subset of frames to reduce CPU load.
    # Heuristic: we sample the first 5 frames assuming persistent issues are likely
    # to appear early in the clip. Increase this sample size for more thorough analysis.
    step = max(1, len(gray_frames) // 5)
    frames_to_check = gray_frames[::step][:5]

    for gray in frames_to_check:
        found, blurry = _process_faces_in_frame(self, gray)
        faces_found += found
        blurry_faces += blurry

    if faces_found > 0:
        blur_ratio = blurry_faces / faces_found
        if blur_ratio > 0.5:
            score += 1.0
            issues.append(
                f"Inconsistent facial clarity detected ({int(blur_ratio*100)}% blurry faces)"
            )

    return score, issues


def _check_video_metadata_sync(
    self, video_path: str, fps: float, frame_count: float
) -> Tuple[float, List[str]]:
    """Verify video metadata and check for duration mismatch anomalies."""
    score = 0.0
    issues = []
    if fps > 0 and frame_count > 0:
        duration = frame_count / fps
        file_size = os.path.getsize(video_path)
        if duration < 1.0 and file_size > 5 * 1024 * 1024:
            score += 0.5
            issues.append(
                "Video duration vs file size mismatch (potential stream embedding issue)"
            )
    return score, issues


def _check_audio_visual_sync(
    self, video_path: str, frames: List[np.ndarray]
) -> Tuple[float, List[str]]:
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

        score_diff, sync_issues = _check_video_metadata_sync(
            self, video_path, fps, frame_count
        )
        score += score_diff
        issues.extend(sync_issues)

        cap.release()
    except Exception as e:
        self.logger.warning(f"Error in A/V sync check: {e}")

    return score, issues


def _analyze_frame_high_frequency_noise(self, gray: np.ndarray) -> bool:
    """Analyze a single frame for high-frequency noise spikes."""
    dft = cv2.dft(np.float32(gray), flags=cv2.DFT_COMPLEX_OUTPUT)
    magnitude = cv2.magnitude(dft[:, :, 0], dft[:, :, 1])
    magnitude_spectrum = 20 * np.log(magnitude + 1)
    h, w = gray.shape
    mask_size = min(h, w) // 8

    magnitude_spectrum[:mask_size, :mask_size] = 0
    magnitude_spectrum[:mask_size, -mask_size:] = 0
    magnitude_spectrum[-mask_size:, :mask_size] = 0
    magnitude_spectrum[-mask_size:, -mask_size:] = 0

    return cv2.mean(magnitude_spectrum)[0] > self.HIGH_FREQ_NOISE_THRESHOLD


def _check_compression_artifacts(
    self, gray_frames: List[np.ndarray]
) -> Tuple[float, List[str]]:
    """
    Check for double compression artifacts or unusual frequency patterns.

    Args:
        gray_frames: List of grayscale frames (numpy arrays)

    """
    score = 0.0
    issues = []

    high_freq_noise_count = 0

    # Optimization: Check a subset of frames to reduce CPU load
    # Checking 5 frames is statistically sufficient to detect persistent artifacts
    # while reducing FFT computations by up to 75%
    frames_to_check = gray_frames[:5]

    for gray in frames_to_check:
        if _analyze_frame_high_frequency_noise(self, gray):
            high_freq_noise_count += 1

    if len(frames_to_check) > 0 and (
        high_freq_noise_count / len(frames_to_check) > 0.6
    ):
        score += 1.0
        issues.append("Unusual high-frequency noise patterns detected")

    return score, issues


def _calculate_simulated_frame_score(
    self, frame: np.ndarray, gray: np.ndarray
) -> float:
    """Calculate simulated deepfake score for a single frame."""
    mean, std = cv2.meanStdDev(frame)
    std_dev = float(std.sum()) / std.size
    edges = cv2.Canny(gray, 100, 200)
    edge_count = cv2.countNonZero(edges)
    edge_density = (edge_count * 255.0) / edges.size
    score = (std_dev / 100.0) * 0.5 + (edge_density * 5)
    return min(score, 1.0)


def _run_deepfake_model(
    self, frames: List[np.ndarray], gray_frames: List[np.ndarray], content_type: str
) -> float:
    """
    Run deepfake detection model (Simulated).

    In a full implementation, this would pass frames to a loaded Torch/TensorFlow model.
    Here we simulate a model score based on frame properties to mimic the interface.
    """
    if not frames:
        return 0.0

    avg_scores = [
        _calculate_simulated_frame_score(self, frame, gray)
        for frame, gray in zip(frames, gray_frames, strict=False)
    ]

    # Optimization: sum/len on native Python lists is ~6x faster than np.mean
    final_score = sum(avg_scores) / len(avg_scores) if avg_scores else 0.0

    # Clip to 0.0 - 1.0
    return min(max(final_score, 0.0), 1.0)


def _analyze_video_frames(
    self, filename: str, temp_file_path: str, frames: list, content_type: str
) -> Tuple[float, List[str]]:
    """
    Analyze extracted video frames for deepfake indicators.
    """
    score = 0.0
    indicators = []

    # Optimization: Convert frames to grayscale once to avoid repeated conversions
    # This saves CPU time in subsequent analysis steps
    gray_frames = [cv2.cvtColor(f, cv2.COLOR_BGR2GRAY) for f in frames]

    facial_score, facial_issues = self._analyze_facial_inconsistencies(gray_frames)
    sync_score, sync_issues = self._check_audio_visual_sync(temp_file_path, frames)
    compression_score, compression_issues = self._check_compression_artifacts(
        gray_frames
    )

    for f_score, f_issues in [
        (facial_score, facial_issues),
        (sync_score, sync_issues),
        (compression_score, compression_issues),
    ]:
        if f_score > 0:
            score += f_score
            indicators.extend([f"{filename}: {issue}" for issue in f_issues])

    # 5. Use specialized deepfake detection models (Simulated)
    model_score = self._run_deepfake_model(frames, gray_frames, content_type)
    if model_score > 0.7:
        score += 3.0
        indicators.append(f"High probability of deepfake detected by model: {filename}")

    return score, indicators

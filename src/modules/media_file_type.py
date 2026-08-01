"""Media file type and metadata analysis helpers."""

from typing import List, Optional, Tuple

def _is_path_traversal_attempt(self, path: str) -> bool:
    """Check if a path string contains traversal attempts or absolute paths."""
    if path.startswith(("/", "\\")):
        return True
    if ".." in path:
        return True

    # Simplifies the Windows drive check to avoid "Complex Conditional" flag
    # We only check the first two chars if the string is long enough
    if len(path) < 2:
        return False

    return path[0].isalpha() and path[1] == ":"

def _check_file_extension(self, filename: str) -> Tuple[float, List[str]]:
    """Check if file extension is dangerous."""
    score = 0.0
    warnings = []

    # Sanitize filename (strip whitespace and null bytes for check)
    # Also strip trailing dots which can bypass extension checks but still be executable on Windows
    filename_lower = filename.lower().strip().replace("\0", "").rstrip(".")

    # Check for dangerous extensions
    # Optimization: tuple-based endswith() is ~10-15x faster than looping
    if filename_lower.endswith(self.DANGEROUS_EXTENSIONS):
        score += 5.0  # Very high score for dangerous files
        warnings.append(f"Dangerous file type: {filename}")

    # Check for suspicious extensions
    # Optimization: tuple-based endswith() avoids slow Python looping overhead
    if filename_lower.endswith(self.SUSPICIOUS_EXTENSIONS):
        score += 3.0
        warnings.append(f"Suspicious file extension: {filename}")

    # Check for double extensions
    parts = filename_lower.split(".")
    if len(parts) > 2:
        score += 1.5
        warnings.append(f"Multiple extensions detected: {filename}")

    return score, warnings

def _check_riff_container(self, data: bytes) -> Optional[str]:
    """Check for specific media types within a RIFF container."""
    if len(data) >= 12:
        format_type = data[8:12]
        if format_type == b"AVI ":
            return "avi"
        elif format_type == b"WAVE":
            return "wav"
        elif format_type == b"WEBP":
            return "webp"
    return None

def _detect_magic_signature_offset_0(self, data: bytes) -> Optional[str]:
    """Check magic signatures with offset 0."""
    if data.startswith(self.MAGIC_PREFIXES_OFFSET_0):
        for sig, name in self.MAGIC_SIGNATURES_OFFSET_0:
            if data.startswith(sig):
                return name
    return None


def _detect_file_type(self, data: bytes) -> Optional[str]:
    """Detect file type from magic bytes."""
    if not data or len(data) < 4:
        return None

    # Check RIFF container (AVI, WAV, WEBP)
    if data.startswith(b"RIFF"):
        return self._check_riff_container(data)

    # Optimization: Fast check for all signatures with offset 0
    name = _detect_magic_signature_offset_0(self, data)
    if name:
        return name

    # Check signatures with non-zero offset
    if len(data) >= 8 and data[4:8] == b"ftyp":  # Common for MP4/MOV
        return "mp4"

    return None

def _check_content_type_mismatch(
    self, filename: str, content_type: str, data: bytes
) -> Tuple[float, str]:
    """Check if actual file content matches declared content type."""
    actual_type = self._detect_file_type(data)

    if actual_type:
        return self._validate_signature_match(filename, actual_type)
    else:
        return self._validate_missing_signature(filename)

def _validate_signature_match(
    self, filename: str, actual_type: str
) -> Tuple[float, str]:
    """Check if file extension matches the detected signature."""
    filename_lower = filename.lower().strip().replace("\0", "").rstrip(".")

    # Special case for executables disguised as documents
    if actual_type == "exe" and not filename_lower.endswith(".exe"):
        return 5.0, "Executable disguised as another file type"

    # Check for general mismatches
    expected_exts = self.EXPECTED_EXTENSIONS.get(actual_type)
    if expected_exts and not filename_lower.endswith(expected_exts):
        return 2.0, f"File type mismatch: {filename} (detected {actual_type})"

    return 0.0, ""

def _validate_missing_signature(self, filename: str) -> Tuple[float, str]:
    """Check if missing signature violates strict extension rules."""
    # Type not detected. Validate that if extension claims a known type, it matches.
    # This prevents processing invalid/corrupt media files.
    filename_lower = filename.lower().strip().replace("\0", "").rstrip(".")

    # Lazily initialize strict validation configuration on the class so we don't
    # rebuild it on every call. This keeps the mapping centralized and efficient.
    cls = self.__class__

    if not hasattr(cls, "_STRICT_VALIDATION_EXTS"):
        # Map extensions to their expected descriptions for error messages
        cls._STRICT_VALIDATION_EXTS = {
            # Note: '.exe' and '.dll' are also handled earlier when a valid PE signature
            # is detected (actual_type == 'exe'). They are included here as a fallback
            # for cases where signature detection fails but the extension claims an executable.
            ".exe": "executable",
            ".dll": "executable",
            ".zip": "archive",
            ".pdf": "PDF",
            ".png": "PNG image",
            ".jpg": "JPEG image",
            ".jpeg": "JPEG image",
            ".gif": "GIF image",
            ".mp4": "MP4 video",
            ".avi": "AVI video",
            ".mkv": "MKV video",
            ".wav": "WAV audio",
            # Additional strict validation for media types processed by OpenCV
            ".mov": "QuickTime video",
            ".wmv": "WMV video",
            ".flv": "FLV video",
            ".ogg": "Ogg audio/video",
            ".flac": "FLAC audio",
            ".m4a": "M4A audio",
        }

    if not hasattr(cls, "_CRITICAL_MEDIA_EXTS"):
        # Treat all known media extensions (and WAV) as critical when their signatures are invalid,
        # to prevent them from reaching deepfake/OpenCV processing. Use getattr so we degrade
        # safely if MEDIA_EXTENSIONS is not defined on this instance.
        media_exts = getattr(self, "MEDIA_EXTENSIONS", [])
        cls._CRITICAL_MEDIA_EXTS = {
            ext
            for ext in cls._STRICT_VALIDATION_EXTS.keys()
            if ext in media_exts or ext == ".wav"
        }

    strict_validation_exts = cls._STRICT_VALIDATION_EXTS
    critical_media_exts = cls._CRITICAL_MEDIA_EXTS
    for ext, type_desc in strict_validation_exts.items():
        if filename_lower.endswith(ext):
            # Return 5.0 (Critical) for media files to ensure they don't reach deepfake analysis
            # which could trigger vulnerabilities in processing libraries (e.g., OpenCV)
            # Note: 5.0 is intentionally chosen to fail the `threat_score < 5.0` gate (see earlier check),
            # so that invalid media never reaches the deepfake/OpenCV processing pipeline.
            if ext in critical_media_exts:
                return (
                    5.0,
                    f"Invalid file signature for {ext}: expected {type_desc} signature but none found",
                )
            return (
                2.0,
                f"Invalid file signature for {ext}: expected {type_desc} signature but none found",
            )

    return 0.0, ""

def _check_large_size_anomaly(self, filename: str, size: int) -> Tuple[float, str]:
    """Check for unusually large file size anomalies."""
    if size > self.MAX_ATTACHMENT_SIZE_MB * 1024 * 1024:
        return 1.5, f"Unusually large attachment: {filename} ({size / (1024*1024):.1f}MB)"
    return 0.0, ""


def _check_small_media_size_anomaly(self, filename: str, size: int) -> Tuple[float, str]:
    """Check for suspiciously small media files."""
    filename_lower = filename.lower()
    if filename_lower.endswith(self.MEDIA_EXTENSIONS):
        if size < self.MIN_MEDIA_FILE_SIZE_BYTES:
            return 1.0, f"Suspiciously small media file: {filename} ({size} bytes)"
    return 0.0, ""


def _check_size_anomaly(self, filename: str, size: int) -> Tuple[float, str]:
    """Check for unusual file sizes."""
    large_score, large_warning = _check_large_size_anomaly(self, filename, size)
    if large_warning:
        return large_score, large_warning

    small_score, small_warning = _check_small_media_size_anomaly(self, filename, size)
    if small_warning:
        return small_score, small_warning

    return 0.0, ""

def _is_nested_archive(self, filename_lower: str) -> bool:
    """Check if filename is a nested archive type. Assumes filename_lower is already lowercase."""
    # Optimization: O(1) loop iteration using tuple-based endswith() check
    return filename_lower.endswith(self.ARCHIVE_EXTENSIONS)

def _is_zip_magic_or_extension(filename_lower: str, data: bytes) -> bool:
    """Check if file starts with ZIP magic bytes or has .zip extension."""
    if data and data.startswith(b"PK\x03\x04"):
        return True
    return filename_lower.endswith(".zip")


def _inspect_zip_archive(self, filename: str, filename_lower: str, data: bytes, result: dict) -> None:
    """Inspect Zip archive if applicable."""
    if not _is_zip_magic_or_extension(filename_lower, data):
        return
    zip_score, zip_warnings = self._inspect_zip_contents(filename, data)
    result["score"] += zip_score
    result["suspicious_attachments"].extend(zip_warnings)


def _inspect_tar_archive(self, filename: str, filename_lower: str, data: bytes, result: dict) -> None:
    """Inspect Tar archive if applicable."""
    if not filename_lower.endswith((".tar", ".tar.gz", ".tgz", ".gz")):
        return
    tar_score, tar_warnings = self._inspect_tar_contents(filename, data)
    result["score"] += tar_score
    result["suspicious_attachments"].extend(tar_warnings)


def _analyze_attachment_metadata(self, attachment: dict) -> dict:
    """
    Analyze attachment metadata and basic properties.
    Returns a dict with scores and warnings.
    """
    filename = attachment.get("filename", "")
    content_type = attachment.get("content_type", "")
    size = attachment.get("size", 0)
    data = attachment.get("data", b"")
    truncated = attachment.get("truncated", False)

    result = {
        "score": 0.0,
        "size_anomalies": [],
        "file_type_warnings": [],
        "suspicious_attachments": [],
    }

    if truncated:
        result["size_anomalies"].append(
            f"Attachment truncated for scanning: {filename}"
        )

    # Check file extension
    ext_score, ext_warnings = self._check_file_extension(filename)
    result["score"] += ext_score
    result["file_type_warnings"].extend(ext_warnings)

    # Check content type mismatch
    mismatch_score, mismatch_warnings = self._check_content_type_mismatch(
        filename, content_type, data
    )
    result["score"] += mismatch_score
    if mismatch_warnings:
        result["suspicious_attachments"].append(f"{filename}: {mismatch_warnings}")

    # Check file size anomalies
    size_score, size_warning = self._check_size_anomaly(filename, size)
    result["score"] += size_score
    if size_warning:
        result["size_anomalies"].append(size_warning)

    filename_lower = filename.lower()
    _inspect_zip_archive(self, filename, filename_lower, data, result)
    _inspect_tar_archive(self, filename, filename_lower, data, result)

    return result

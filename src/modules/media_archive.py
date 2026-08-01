"""Archive inspection helpers for ZIP and TAR files."""

import io
import tarfile
import zipfile
from typing import List, Tuple

from ..utils.sanitization import sanitize_for_logging
from ..utils.security_validators import sanitize_filename

def _inspect_zip_contents(
    self, filename: str, data: bytes, depth: int = 0
) -> Tuple[float, List[str]]:
    """Inspect contents of zip file for dangerous files, with recursion."""
    score = 0.0
    warnings = []

    # Max recursion depth to prevent zip bombs
    if depth > 2:
        return score, warnings

    try:
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            file_list = zf.namelist()
            score, warnings = self._check_file_count(
                filename, file_list, score, warnings
            )

            # Always cap the number of files we inspect to MAX_ZIP_FILE_COUNT to limit processing
            files_to_check = file_list[: self.MAX_ZIP_FILE_COUNT]

            for contained_file in files_to_check:
                member_score, member_warnings = (
                    self._inspect_zip_member_and_check_traversal(
                        zf, contained_file, filename, depth
                    )
                )
                score += member_score
                warnings.extend(member_warnings)

                if score >= 5.0:
                    return score, warnings

    except zipfile.BadZipFile as e:
        self.logger.warning(f"Bad zip file {filename}: {e}")
    except Exception as e:
        self.logger.warning(f"Error inspecting zip {filename}: {e}")

    return score, warnings

def _check_file_count(
    self, filename: str, file_list: List[str], score: float, warnings: List[str]
) -> Tuple[float, List[str]]:
    """Check if archive contains too many files."""
    if len(file_list) > self.MAX_ZIP_FILE_COUNT:
        score += 1.0
        warnings.append(
            f"Archive {filename} contains too many files ({len(file_list)})"
        )
    return score, warnings

def _inspect_zip_member_and_check_traversal(
    self, zf: zipfile.ZipFile, contained_file: str, filename: str, depth: int
) -> Tuple[float, List[str]]:
    score = 0.0
    warnings = []
    if self._is_path_traversal_attempt(contained_file):
        score += 5.0
        safe_contained_file = sanitize_for_logging(
            sanitize_filename(contained_file)
        )
        warnings.append(
            f"Zip file {filename} contains path traversal attempt: {safe_contained_file}"
        )

    member_score, member_warnings = self._inspect_archive_member(
        filename,
        contained_file,
        lambda: self._handle_nested_zip_member(zf, contained_file, filename, depth),
    )
    score += member_score
    warnings.extend(member_warnings)
    return score, warnings

def _inspect_archive_member(
    self, parent_filename: str, member_name: str, nested_handler_fn
) -> Tuple[float, List[str]]:
    """
    Inspect a single member of an archive.

    Args:
        parent_filename: Name of the parent archive
        member_name: Name of the member file
        nested_handler_fn: Function to call if member is a nested archive

    Returns:
        Tuple of (score, warnings)

    """
    score = 0.0
    warnings = []

    # SECURITY: Sanitize member name to prevent path traversal and log injection
    safe_member_name = sanitize_for_logging(sanitize_filename(member_name))
    member_lower = safe_member_name.lower()

    # Check for dangerous extensions
    # Optimization: O(1) loop iteration using tuple-based endswith() check
    if member_lower.endswith(self.DANGEROUS_EXTENSIONS):
        score += 5.0
        warnings.append(
            f"Archive {parent_filename} contains dangerous file: {safe_member_name}"
        )
        return score, warnings

    # Check for nested archives
    is_nested = self._is_nested_archive(member_lower)
    if is_nested:
        score += 2.0
        warnings.append(
            f"Archive {parent_filename} contains nested archive: {safe_member_name}"
        )

        # Recurse
        nested_score, nested_warnings = nested_handler_fn()
        score += nested_score
        warnings.extend(nested_warnings)

        if score >= 5.0:
            return score, warnings

    # Check for suspicious extensions
    # Optimization: O(1) loop iteration using tuple-based endswith() check
    if member_lower.endswith(self.SUSPICIOUS_EXTENSIONS):
        score += 3.0
        warnings.append(
            f"Archive {parent_filename} contains suspicious file: {safe_member_name}"
        )

    return score, warnings

def _is_supported_nested_archive(member_lower: str, depth: int) -> bool:
    """Check if the nested archive is supported and within depth limit."""
    if depth >= 2:
        return False
    supported_extensions = (".zip", ".tar", ".tar.gz", ".tgz", ".gz")
    return member_lower.endswith(supported_extensions)


def _inspect_nested_data(
    self, member_lower: str, nested_path: str, nested_data: bytes, depth: int
) -> Tuple[float, List[str]]:
    """Inspect nested archive data recursively based on file type."""
    if member_lower.endswith(".zip"):
        return self._inspect_zip_contents(nested_path, nested_data, depth + 1)
    return self._inspect_tar_contents(nested_path, nested_data, depth + 1)


def _handle_nested_zip_member(
    self, zf: zipfile.ZipFile, member_name: str, parent_filename: str, depth: int
) -> Tuple[float, List[str]]:
    """Handle nested archive found inside a zip file."""
    score = 0.0
    warnings = []

    # SECURITY: Sanitize member name for logging and recursive path building
    safe_member_name = sanitize_for_logging(sanitize_filename(member_name))
    member_lower = safe_member_name.lower()

    # Only recurse into supported formats
    if not _is_supported_nested_archive(member_lower, depth):
        return score, warnings

    try:
        # Check declared size
        info = zf.getinfo(member_name)
        if info.file_size >= self.MAX_NESTED_ZIP_SIZE:
            self.logger.warning(
                f"Skipping nested archive {safe_member_name} (declared size {info.file_size} > limit)"
            )
            return score, warnings

        # Extract securely
        nested_data = self._read_zip_member_securely(
            zf, member_name, self.MAX_NESTED_ZIP_SIZE
        )

        # Recurse based on type
        nested_path = f"{parent_filename}/{safe_member_name}"
        return _inspect_nested_data(
            self, member_lower, nested_path, nested_data, depth
        )

    except ValueError as e:
        score += 5.0
        warnings.append(
            f"Zip bomb detected: {parent_filename}/{safe_member_name} ({str(e)})"
        )
    except Exception as e:
        self.logger.warning(
            f"Error inspecting nested archive {safe_member_name}: {e}"
        )
        score += 3.0
        warnings.append(
            f"Failed to inspect nested archive {safe_member_name}: {str(e)}"
        )

    return score, warnings

def _inspect_tar_contents(
    self, filename: str, data: bytes, depth: int = 0
) -> Tuple[float, List[str]]:
    """Inspect contents of tar file for dangerous files, with recursion."""
    if depth > 2:
        return 0.0, []

    try:
        return self._inspect_tar_contents_safe(filename, data)
    except tarfile.TarError as e:
        self.logger.warning(f"Error inspecting tar {filename}: {e}")
    except Exception as e:
        self.logger.warning(f"Error inspecting tar {filename}: {e}")

    return 0.0, []

def _inspect_tar_contents_safe(
    self, filename: str, data: bytes
) -> Tuple[float, List[str]]:
    """Safely inspect tar contents with proper filtering and member processing."""
    score = 0.0
    warnings = []

    with tarfile.open(fileobj=io.BytesIO(data), mode="r:*") as tf:
        self._apply_tar_filter(tf)
        members = self._get_tar_members_safely(tf)

        score, warnings = self._check_file_count(
            filename, [m.name for m in members], score, warnings
        )

        for member in members[: self.MAX_ZIP_FILE_COUNT]:
            member_score, member_warnings = self._process_tar_member(
                tf, member, filename
            )
            score += member_score
            warnings.extend(member_warnings)
            if score >= 5.0:
                return score, warnings

    return score, warnings

def _apply_tar_filter(self, tf: tarfile.TarFile) -> None:
    """Apply PEP-706 data filter if available to prevent extraction traversal."""
    if hasattr(tarfile, "data_filter"):
        tf.extraction_filter = getattr(
            tarfile, "data_filter", (lambda member, path: member)
        )

def _get_tar_members_safely(self, tf: tarfile.TarFile) -> List[tarfile.TarInfo]:
    """Get tar members safely with count limit."""
    members = []
    for m in tf:
        members.append(m)
        if len(members) > self.MAX_ZIP_FILE_COUNT:
            break
    return members

def _process_tar_member(
    self, tf: tarfile.TarFile, member: tarfile.TarInfo, filename: str
) -> Tuple[float, List[str]]:
    """Process a single tar member for threats."""
    safe_member_name = sanitize_for_logging(sanitize_filename(member.name))
    member_lower = safe_member_name.lower()

    if member_lower.endswith(self.DANGEROUS_EXTENSIONS):
        return 5.0, [
            f"Archive {filename} contains dangerous file: {safe_member_name}"
        ]

    if self._is_path_traversal_attempt(member.name):
        safe_member_name_traversal = sanitize_for_logging(
            sanitize_filename(member.name)
        )
        return 5.0, [
            f"Tar file {filename} contains path traversal attempt: {safe_member_name_traversal}"
        ]

    if member.issym() or member.islnk():
        if self._is_path_traversal_attempt(member.linkname):
            safe_linkname_traversal = sanitize_for_logging(
                sanitize_filename(member.linkname)
            )
            return 5.0, [
                f"Tar file {filename} contains link with path traversal attempt: {safe_linkname_traversal}"
            ]

    member_score, member_warnings = self._inspect_archive_member(
        filename,
        member.name,
        lambda: self._handle_nested_tar_member(tf, member, filename, 0),
    )
    return member_score, member_warnings

def _handle_nested_tar_member(
    self,
    tf: tarfile.TarFile,
    member: tarfile.TarInfo,
    parent_filename: str,
    depth: int,
) -> Tuple[float, List[str]]:
    """Handle nested archive found inside a tar file."""
    score = 0.0
    warnings = []
    member_name = member.name

    # SECURITY: Sanitize member name for logging and recursive path building
    safe_member_name = sanitize_for_logging(sanitize_filename(member_name))
    member_lower = safe_member_name.lower()

    if not _is_supported_nested_archive(member_lower, depth):
        return score, warnings

    # Skip if declared size is too large
    if member.size >= self.MAX_NESTED_ZIP_SIZE:
        self.logger.warning(
            f"Skipping nested archive {safe_member_name} (declared size {member.size} > limit)"
        )
        return score, warnings

    try:
        f = tf.extractfile(member)
        if f:
            nested_data = self._read_file_securely(
                f, member_name, self.MAX_NESTED_ZIP_SIZE
            )

            nested_path = f"{parent_filename}/{safe_member_name}"
            return _inspect_nested_data(
                self, member_lower, nested_path, nested_data, depth
            )

    except Exception as e:
        self.logger.warning(
            f"Error inspecting nested archive {safe_member_name} inside tar: {e}"
        )
        score += 3.0
        warnings.append(
            f"Failed to inspect nested archive {safe_member_name}: {str(e)}"
        )

    return score, warnings

def _read_file_securely(self, f, filename: str, max_size: int) -> bytes:
    """
    Read a file-like object securely with a size limit.
    """
    content = io.BytesIO()
    total_read = 0
    chunk_size = 8192

    while True:
        chunk = f.read(chunk_size)
        if not chunk:
            break
        total_read += len(chunk)
        if total_read > max_size:
            raise ValueError(
                f"File {filename} exceeds maximum size of {max_size} bytes"
            )
        content.write(chunk)

    return content.getvalue()

def _read_zip_member_securely(
    self, zf: zipfile.ZipFile, filename: str, max_size: int
) -> bytes:
    """
    Read a zip member securely with a size limit to prevent zip bombs.

    Args:
        zf: ZipFile object
        filename: Name of the file to read
        max_size: Maximum allowed size in bytes

    Returns:
        Decompressed bytes

    Raises:
        ValueError: If decompressed size exceeds max_size

    """
    content = io.BytesIO()
    total_read = 0
    chunk_size = 8192

    # Don't use 'with' to avoid implicit close() which might trigger CRC check on partial read
    # causing the ValueError to be masked by BadZipFile exception
    f = zf.open(filename)
    try:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            total_read += len(chunk)
            if total_read > max_size:
                raise ValueError(
                    f"Zip member {filename} exceeds maximum size of {max_size} bytes"
                )
            content.write(chunk)
    finally:
        try:
            f.close()
        except zipfile.BadZipFile as e:
            # Ignore errors on close (like CRC mismatch due to partial read)
            self.logger.debug(
                f"Ignored error closing zip stream for {filename}: {e}"
            )

    return content.getvalue()

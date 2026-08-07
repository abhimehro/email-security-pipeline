import re

with open("src/modules/media_analyzer.py", "r") as f:
    content = f.read()

# Let's extract out the "try/finally" logic to further reduce complexity of _check_deepfake_indicators.

orig_method = """    def _check_deepfake_indicators(
        self, filename: str, data: bytes, content_type: str
    ) -> Tuple[float, List[str]]:
        \"\"\"
        Check for potential deepfake indicators using advanced analysis.
        \"\"\"
        score = 0.0
        indicators = []

        filename_lower = filename.lower()

        is_media = filename_lower.endswith(self.MEDIA_EXTENSIONS)
        if not is_media:
            return score, indicators

        if filename_lower.endswith((".mp4", ".avi", ".mov")) and len(data) < 100 * 1024:
            score += 0.5
            indicators.append(f"Suspicious video size: {filename}")

        if not self.config.deepfake_detection_enabled:
            return score, indicators

        temp_file_path = None
        try:
            with tempfile.NamedTemporaryFile(
                delete=False, suffix=os.path.splitext(filename)[1]
            ) as temp_file:
                temp_file_path = temp_file.name
                temp_file.write(data)

            fs, fi = self._process_deepfake_temp_file(filename, temp_file_path, content_type)
            score += fs
            indicators.extend(fi)

        except Exception as e:
            self.logger.error(f"Error during deepfake analysis for {filename}: {str(e)}")
        finally:
            if temp_file_path and os.path.exists(temp_file_path):
                try:
                    os.unlink(temp_file_path)
                except OSError as e:
                    self.logger.warning(
                        f"Failed to delete temp file {temp_file_path}: {e}"
                    )

        return score, indicators"""

new_method = """    def _run_deepfake_temp_file(self, filename: str, data: bytes, content_type: str) -> Tuple[float, List[str]]:
        temp_file_path = None
        score = 0.0
        indicators = []
        try:
            with tempfile.NamedTemporaryFile(
                delete=False, suffix=os.path.splitext(filename)[1]
            ) as temp_file:
                temp_file_path = temp_file.name
                temp_file.write(data)

            score, indicators = self._process_deepfake_temp_file(filename, temp_file_path, content_type)
        except Exception as e:
            self.logger.error(f"Error during deepfake analysis for {filename}: {str(e)}")
        finally:
            if temp_file_path and os.path.exists(temp_file_path):
                try:
                    os.unlink(temp_file_path)
                except OSError as e:
                    self.logger.warning(
                        f"Failed to delete temp file {temp_file_path}: {e}"
                    )
        return score, indicators

    def _check_deepfake_indicators(
        self, filename: str, data: bytes, content_type: str
    ) -> Tuple[float, List[str]]:
        \"\"\"
        Check for potential deepfake indicators using advanced analysis.
        \"\"\"
        score = 0.0
        indicators = []

        filename_lower = filename.lower()

        if not filename_lower.endswith(self.MEDIA_EXTENSIONS):
            return score, indicators

        if filename_lower.endswith((".mp4", ".avi", ".mov")) and len(data) < 102400:
            score += 0.5
            indicators.append(f"Suspicious video size: {filename}")

        if not getattr(self.config, "deepfake_detection_enabled", False):
            return score, indicators

        fs, fi = self._run_deepfake_temp_file(filename, data, content_type)
        score += fs
        indicators.extend(fi)

        return score, indicators"""

content = content.replace(orig_method, new_method)

with open("src/modules/media_analyzer.py", "w") as f:
    f.write(content)

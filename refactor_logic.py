import re

with open('src/modules/media_analyzer.py', 'r') as f:
    content = f.read()

search_pattern = r"""    def _extract_frames_sampled\(
        self, cap, total_frames: int, step: int, max_frames: int, max_dim: int
    \) -> List\[np\.ndarray\]:
        \"\"\"Extract frames using a hybrid approach of seeking and grabbing for sampling\.\"\"\"
        frames = \[\]
        current_frame = 0

        # Performance optimization:
        # cv2\.VideoCapture\.set\(CAP_PROP_POS_FRAMES\) is slow for small forward jumps\.
        # cap\.grab\(\) is much faster for skipping a small number of frames sequentially\.
        # We use a hybrid approach: grab for small jumps \(<= 30 frames\), set for large jumps\.
        seek_threshold = 30

        for target_frame in range\(0, total_frames, step\):
            if len\(frames\) >= max_frames:
                break

            jump = target_frame - current_frame

            if jump > seek_threshold:
                cap\.set\(cv2\.CAP_PROP_POS_FRAMES, target_frame\)
                current_frame = target_frame

            # Skip frames using grab\(\) if we are behind the target frame
            while current_frame < target_frame:
                if not cap\.grab\(\):
                    break
                current_frame \+= 1

            if current_frame != target_frame:
                break

            success, frame = cap\.read\(\)
            if success and frame is not None:
                frames\.append\(self\._resize_frame_if_needed\(frame, max_dim\)\)
                current_frame \+= 1
            else:
                break

        return frames"""

replace_pattern = """    def _extract_frames_sampled(
        self, cap, total_frames: int, step: int, max_frames: int, max_dim: int
    ) -> List[np.ndarray]:
        \"\"\"Extract frames using a hybrid approach of seeking and grabbing for sampling.\"\"\"
        frames = []
        current_frame = 0

        for target_frame in range(0, total_frames, step):
            if len(frames) >= max_frames:
                break

            current_frame = self._advance_to_frame(cap, current_frame, target_frame)

            if current_frame != target_frame:
                break

            success, frame = cap.read()
            if success and frame is not None:
                frames.append(self._resize_frame_if_needed(frame, max_dim))
                current_frame += 1
            else:
                break

        return frames

    def _advance_to_frame(self, cap, current_frame: int, target_frame: int) -> int:
        \"\"\"Advance the video capture to the target frame using a hybrid approach.\"\"\"
        import cv2
        seek_threshold = 30
        jump = target_frame - current_frame

        if jump > seek_threshold:
            cap.set(cv2.CAP_PROP_POS_FRAMES, target_frame)
            current_frame = target_frame

        while current_frame < target_frame:
            if not cap.grab():
                break
            current_frame += 1

        return current_frame"""

if re.search(search_pattern, content):
    new_content = re.sub(search_pattern, replace_pattern, content)
    with open('src/modules/media_analyzer.py', 'w') as f:
        f.write(new_content)
    print("Successfully replaced.")
else:
    print("Pattern not found.")

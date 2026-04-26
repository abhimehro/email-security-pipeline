import re

with open('src/modules/media_analyzer.py', 'r') as f:
    content = f.read()

search_pattern = r"""    def _advance_to_frame\(self, cap, current_frame: int, target_frame: int\) -> int:
        \"\"\"Advance the video capture to the target frame using a hybrid approach\.\"\"\"
        seek_threshold = 30
        jump = target_frame - current_frame

        if jump > seek_threshold:
            cap\.set\(cv2\.CAP_PROP_POS_FRAMES, target_frame\)
            current_frame = target_frame"""

replace_pattern = """    def _advance_to_frame(self, cap, current_frame: int, target_frame: int) -> int:
        \"\"\"Advance the video capture to the target frame using a hybrid approach.\"\"\"
        try:
            import cv2
            cap_prop_pos_frames = cv2.CAP_PROP_POS_FRAMES
        except ImportError:
            cap_prop_pos_frames = 1  # Fallback to the known integer value for CAP_PROP_POS_FRAMES

        seek_threshold = 30
        jump = target_frame - current_frame

        if jump > seek_threshold:
            cap.set(cap_prop_pos_frames, target_frame)
            current_frame = target_frame"""

if re.search(search_pattern, content):
    new_content = re.sub(search_pattern, replace_pattern, content)
    with open('src/modules/media_analyzer.py', 'w') as f:
        f.write(new_content)
    print("Successfully replaced.")
else:
    print("Pattern not found.")

import cv2
import numpy as np
import time
import os
import tempfile
from typing import List

def create_dummy_video(filename, frames=100, width=640, height=480):
    fourcc = cv2.VideoWriter_fourcc(*'mp4v')
    out = cv2.VideoWriter(filename, fourcc, 20.0, (width, height))
    if not out.isOpened():
        print("Failed to open video writer")
        return False
    for _ in range(frames):
        # Create a frame with some pattern to avoid compression being too efficient?
        # Random noise is fine.
        frame = np.random.randint(0, 255, (height, width, 3), dtype=np.uint8)
        out.write(frame)
    out.release()
    return True

def _resize_frame_if_needed(frame: np.ndarray, max_dim: int = 1920) -> np.ndarray:
    try:
        h, w = frame.shape[:2]
        if h <= 0 or w <= 0: return frame
        if max(h, w) <= max_dim: return frame
        scale = max_dim / max(h, w)
        new_w = max(1, int(w * scale))
        new_h = max(1, int(h * scale))
        return cv2.resize(frame, (new_w, new_h), interpolation=cv2.INTER_AREA)
    except Exception:
        return frame

def extract_frames_original(video_path: str, max_frames: int = 10, max_dim: int = 1920) -> List[np.ndarray]:
    frames = []
    try:
        cap = cv2.VideoCapture(video_path)
        if not cap.isOpened():
            return frames

        total_frames = int(cap.get(cv2.CAP_PROP_FRAME_COUNT))
        if total_frames <= 0:
            success, frame = cap.read()
            count = 0
            while success and count < max_frames:
                if frame is not None:
                    frames.append(_resize_frame_if_needed(frame, max_dim))
                success, frame = cap.read()
                count += 1
        else:
            step = max(1, total_frames // max_frames)
            for i in range(0, total_frames, step):
                cap.set(cv2.CAP_PROP_POS_FRAMES, i)
                success, frame = cap.read()
                if success and frame is not None:
                    frames.append(_resize_frame_if_needed(frame, max_dim))
                if len(frames) >= max_frames:
                    break
        cap.release()
    except Exception as e:
        print(f"Error: {e}")
    return frames

def extract_frames_optimized(video_path: str, max_frames: int = 10, max_dim: int = 1920) -> List[np.ndarray]:
    frames = []
    try:
        cap = cv2.VideoCapture(video_path)
        if not cap.isOpened():
            return frames

        total_frames = int(cap.get(cv2.CAP_PROP_FRAME_COUNT))
        if total_frames <= 0:
            success, frame = cap.read()
            count = 0
            while success and count < max_frames:
                if frame is not None:
                    frames.append(_resize_frame_if_needed(frame, max_dim))
                success, frame = cap.read()
                count += 1
        else:
            step = max(1, total_frames // max_frames)
            # Optimization: If step is 1, read sequentially to avoid expensive seek
            if step == 1:
                count = 0
                while count < max_frames:
                     success, frame = cap.read()
                     if not success:
                         break
                     if frame is not None:
                         frames.append(_resize_frame_if_needed(frame, max_dim))
                     count += 1
            else:
                for i in range(0, total_frames, step):
                    cap.set(cv2.CAP_PROP_POS_FRAMES, i)
                    success, frame = cap.read()
                    if success and frame is not None:
                        frames.append(_resize_frame_if_needed(frame, max_dim))
                    if len(frames) >= max_frames:
                        break
        cap.release()
    except Exception as e:
        print(f"Error: {e}")
    return frames

# Test
with tempfile.NamedTemporaryFile(suffix='.mp4', delete=False) as tf:
    video_path = tf.name

try:
    print("Creating dummy video...")
    if create_dummy_video(video_path, frames=50, width=640, height=480):
        max_frames = 100 # step will be 1

        print("Benchmarking Short Video (step=1)...")
        start = time.time()
        frames_orig = extract_frames_original(video_path, max_frames=max_frames)
        dur_orig = time.time() - start

        start = time.time()
        frames_opt = extract_frames_optimized(video_path, max_frames=max_frames)
        dur_opt = time.time() - start

        print(f"Short video (step=1): Original={dur_orig:.4f}s ({len(frames_orig)} frames), Optimized={dur_opt:.4f}s ({len(frames_opt)} frames)")

        # Scenario 2: Long video -> step > 1
        # We can reuse the same video but ask for fewer frames to force step > 1
        # Video has 50 frames. If we ask for 5 frames, step = 10.

        max_frames_long = 5
        print("Benchmarking Long Video simulation (step=10)...")
        start = time.time()
        frames_orig = extract_frames_original(video_path, max_frames=max_frames_long)
        dur_orig = time.time() - start

        start = time.time()
        frames_opt = extract_frames_optimized(video_path, max_frames=max_frames_long)
        dur_opt = time.time() - start

        print(f"Long video (step=10): Original={dur_orig:.4f}s ({len(frames_orig)} frames), Optimized={dur_opt:.4f}s ({len(frames_opt)} frames)")

    else:
        print("Skipping benchmark as video creation failed.")

finally:
    if os.path.exists(video_path):
        os.remove(video_path)

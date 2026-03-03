import re
import timeit
import cv2
import numpy as np

# Simulate a frame
frame = np.random.randint(0, 256, (1080, 1920, 3), dtype=np.uint8)

def with_np_mean():
    return np.mean(frame)

def with_cv2_mean():
    return cv2.mean(frame)[0]

print(f"np mean: {timeit.timeit(with_np_mean, number=100)}")
print(f"cv2 mean: {timeit.timeit(with_cv2_mean, number=100)}")

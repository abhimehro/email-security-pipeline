import timeit

def bench_before():
    def _validate_signature_match(filename: str, actual_type: str):
        filename_lower = filename.lower().strip().replace('\0', '').rstrip('.')
        if actual_type == 'exe' and not filename_lower.endswith('.exe'):
            return 5.0, "Executable disguised as another file type"

        expected_extensions = {
            'pdf': ['.pdf'],
            'zip': ['.zip', '.docx', '.xlsx', '.pptx', '.jar'],
            'jpeg': ['.jpg', '.jpeg'],
            'png': ['.png'],
            'gif': ['.gif'],
            'doc': ['.doc', '.xls', '.ppt', '.msi'],
            'exe': ['.exe'],
            'mp4': ['.mp4', '.mov', '.m4a', '.3gp'],
            'avi': ['.avi'],
            'wav': ['.wav'],
            'mp3': ['.mp3'],
            'mkv': ['.mkv', '.webm'],
            'webp': ['.webp'],
            'wmv': ['.wmv'],
            'flv': ['.flv'],
            'ogg': ['.ogg', '.oga', '.ogv', '.ogx'],
            'flac': ['.flac'],
        }

        if actual_type in expected_extensions:
            expected_exts = tuple(expected_extensions[actual_type])
            if not filename_lower.endswith(expected_exts):
                return 2.0, "Mismatch"

        return 0.0, ""

    for _ in range(1000):
        _validate_signature_match("test.docx", "zip")

def bench_after():
    EXPECTED_EXTENSIONS = {
        'pdf': ('.pdf',),
        'zip': ('.zip', '.docx', '.xlsx', '.pptx', '.jar'),
        'jpeg': ('.jpg', '.jpeg'),
        'png': ('.png',),
        'gif': ('.gif',),
        'doc': ('.doc', '.xls', '.ppt', '.msi'),
        'exe': ('.exe',),
        'mp4': ('.mp4', '.mov', '.m4a', '.3gp'),
        'avi': ('.avi',),
        'wav': ('.wav',),
        'mp3': ('.mp3',),
        'mkv': ('.mkv', '.webm'),
        'webp': ('.webp',),
        'wmv': ('.wmv',),
        'flv': ('.flv',),
        'ogg': ('.ogg', '.oga', '.ogv', '.ogx'),
        'flac': ('.flac',),
    }

    def _validate_signature_match(filename: str, actual_type: str):
        filename_lower = filename.lower().strip().replace('\0', '').rstrip('.')
        if actual_type == 'exe' and not filename_lower.endswith('.exe'):
            return 5.0, "Executable disguised as another file type"

        if actual_type in EXPECTED_EXTENSIONS:
            expected_exts = EXPECTED_EXTENSIONS[actual_type]
            if not filename_lower.endswith(expected_exts):
                return 2.0, "Mismatch"

        return 0.0, ""

    for _ in range(1000):
        _validate_signature_match("test.docx", "zip")

t_before = timeit.timeit(bench_before, number=100)
t_after = timeit.timeit(bench_after, number=100)
print(f"Before: {t_before:.4f}s")
print(f"After:  {t_after:.4f}s")
print(f"Speedup: {t_before / t_after:.2f}x")

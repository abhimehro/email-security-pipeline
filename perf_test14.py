import timeit

ARCHIVE_EXTENSIONS = {'.zip', '.rar', '.7z', '.tar', '.gz', '.iso', '.img', '.vhd', '.vhdx'}
ARCHIVE_EXTENSIONS_TUPLE = tuple(ARCHIVE_EXTENSIONS)

def check_any():
    filename = "test_document_final_v2_really.doc.zip"
    return any(filename.lower().endswith(ext) for ext in ARCHIVE_EXTENSIONS)

def check_tuple():
    filename = "test_document_final_v2_really.doc.zip"
    return filename.lower().endswith(ARCHIVE_EXTENSIONS_TUPLE)

print(f"any: {timeit.timeit(check_any, number=1000000)}")
print(f"tuple: {timeit.timeit(check_tuple, number=1000000)}")

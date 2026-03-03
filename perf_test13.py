import timeit

def list_comprehension_str_replace():
    # simulating media_analyzer
    filename = "test.jpg.exe"
    return filename.lower().strip().replace('\0', '').rstrip('.')

def str_replace_opt():
    filename = "test.jpg.exe"
    # Is there a better way?
    return filename.lower().strip().replace('\0', '').rstrip('.')

print(f"1: {timeit.timeit(list_comprehension_str_replace, number=1000000)}")
print(f"2: {timeit.timeit(str_replace_opt, number=1000000)}")

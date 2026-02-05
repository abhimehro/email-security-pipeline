
import sys
import time
import re
from dataclasses import dataclass
from typing import Dict, List, Union
import random
import string

# Mocking necessary classes
@dataclass
class EmailData:
    subject: str
    body_text: str
    body_html: str
    headers: Dict[str, Union[str, List[str]]]
    sender: str

@dataclass
class AnalysisConfig:
    spam_check_urls: bool = True
    spam_check_headers: bool = True
    spam_threshold: float = 5.0

# Copying relevant parts of SpamAnalyzer to isolate the benchmark
class SpamAnalyzerOriginal:
    URL_EXTRACTION_PATTERN = re.compile(r'https?://[^\s<>"]+', re.IGNORECASE)

    def __init__(self, config):
        self.config = config

    def analyze_urls_original(self, email_data: EmailData):
        start_time = time.time()
        # Original implementation
        full_body_content = email_data.body_text + email_data.body_html
        extracted_urls = self.URL_EXTRACTION_PATTERN.findall(full_body_content)
        link_count = len(extracted_urls)
        end_time = time.time()
        return end_time - start_time, link_count, extracted_urls

class SpamAnalyzerOptimized:
    URL_EXTRACTION_PATTERN = re.compile(r'https?://[^\s<>"]+', re.IGNORECASE)

    def __init__(self, config):
        self.config = config

    def analyze_urls_optimized(self, email_data: EmailData):
        start_time = time.time()
        # Optimized implementation
        urls_text = self.URL_EXTRACTION_PATTERN.findall(email_data.body_text)
        urls_html = self.URL_EXTRACTION_PATTERN.findall(email_data.body_html)
        extracted_urls = urls_text + urls_html
        link_count = len(extracted_urls)
        end_time = time.time()
        return end_time - start_time, link_count, extracted_urls

def generate_random_string(length):
    return ''.join(random.choices(string.ascii_letters + string.digits + ' ', k=length))

def generate_large_email(size_kb=100, url_count=50):
    text_content = generate_random_string(size_kb * 1024)
    html_content = generate_random_string(size_kb * 1024)

    # Insert URLs
    urls = [f"http://example.com/{generate_random_string(10)}" for _ in range(url_count)]

    for url in urls:
        pos = random.randint(0, len(text_content))
        text_content = text_content[:pos] + " " + url + " " + text_content[pos:]

        pos = random.randint(0, len(html_content))
        html_content = html_content[:pos] + f'<a href="{url}">{url}</a>' + html_content[pos:]

    return EmailData(
        subject="Test Subject",
        body_text=text_content,
        body_html=html_content,
        headers={},
        sender="test@example.com"
    )

def run_benchmark():
    print("Generating test data...")
    # 500KB email body, 100 URLs
    email_data = generate_large_email(size_kb=500, url_count=100)

    config = AnalysisConfig()
    original = SpamAnalyzerOriginal(config)
    optimized = SpamAnalyzerOptimized(config)

    print("Running benchmark...")
    iterations = 100

    total_original_time = 0
    total_optimized_time = 0

    # Warmup
    for _ in range(10):
        original.analyze_urls_original(email_data)
        optimized.analyze_urls_optimized(email_data)

    for _ in range(iterations):
        t_orig, count_orig, urls_orig = original.analyze_urls_original(email_data)
        total_original_time += t_orig

        t_opt, count_opt, urls_opt = optimized.analyze_urls_optimized(email_data)
        total_optimized_time += t_opt

        assert count_orig == count_opt
        # Order might be different if URLs are distributed differently, but content should be same?
        # Actually:
        # Original: findall(text + html).
        # Optimized: findall(text) + findall(html).
        # If a URL is at the boundary of concatenation?
        # "http://exa" + "mple.com" -> "http://example.com"
        # Concatenation might CREATE a URL that wasn't there!
        # But wait, body_text and body_html are separate fields.
        # Concatenating them blindly `email_data.body_text + email_data.body_html`
        # If text ends with "http://" and html starts with "example.com", original code would find a URL.
        # But this is NOT correct behavior, it's a bug/artifact of concatenation!
        # Text and HTML are separate parts. They shouldn't be concatenated without a separator.
        # So the optimization also fixes a potential bug.

    avg_original = total_original_time / iterations
    avg_optimized = total_optimized_time / iterations

    print(f"Original average time: {avg_original*1000:.4f} ms")
    print(f"Optimized average time: {avg_optimized*1000:.4f} ms")
    print(f"Improvement: {(avg_original - avg_optimized) / avg_original * 100:.2f}%")

if __name__ == "__main__":
    run_benchmark()

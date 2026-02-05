
import time
import re
import random
import string

SPAM_KEYWORDS = [
    r"\b(viagra|cialis|pharmacy|pills)\b",
    r"\b(winner|congratulations|prize|lottery)\b",
    r"\b(urgent|immediate|action required|act now)\b",
    r"\b(click here|click now|limited time)\b",
    r"\b(free money|make money|earn cash)\b",
    r"\b(nigerian prince|inheritance|beneficiary)\b",
    r"\b(enlarge|enhancement|weight loss)\b",
    r"\b(casino|poker|gambling)\b",
]

def generate_text(size_kb=100):
    # Generate random text with some spam keywords
    words = ["hello", "world", "this", "is", "a", "test", "email", "content"]
    text = []
    for _ in range(size_kb * 100):
        text.append(random.choice(words))

    # Insert keywords
    spam_words = ["viagra", "winner", "urgent", "click here", "free money"]
    for _ in range(50):
        pos = random.randint(0, len(text))
        text.insert(pos, random.choice(spam_words))

    return " ".join(text)

class RegexBenchmark:
    def __init__(self):
        # Original: | joined
        self.original_pattern = re.compile("|".join(SPAM_KEYWORDS), re.IGNORECASE)

        # Optimized: flattened and wrapped in one \b...\b
        all_keywords = []
        for p in SPAM_KEYWORDS:
            # naive stripping for this specific list structure
            inner = p.replace(r"\b", "").strip("()")
            all_keywords.append(inner)

        combined_inner = "|".join(all_keywords)
        self.optimized_pattern = re.compile(r"\b(?:" + combined_inner + r")\b", re.IGNORECASE)

        # Another optimization: use re.sub or something? No, we need count.

    def bench(self, text):
        start = time.time()
        matches = sum(1 for _ in self.original_pattern.finditer(text))
        t_orig = time.time() - start

        start = time.time()
        matches_opt = sum(1 for _ in self.optimized_pattern.finditer(text))
        t_opt = time.time() - start

        assert matches == matches_opt, f"Matches differ: {matches} vs {matches_opt}"
        return t_orig, t_opt

def run():
    print("Generating text...")
    text = generate_text(size_kb=500)
    print(f"Text length: {len(text)}")

    benchmark = RegexBenchmark()

    print("Running benchmark...")
    iterations = 50
    total_orig = 0
    total_opt = 0

    # Warmup
    benchmark.bench(text)

    for _ in range(iterations):
        t_orig, t_opt = benchmark.bench(text)
        total_orig += t_orig
        total_opt += t_opt

    print(f"Original avg: {total_orig/iterations*1000:.4f} ms")
    print(f"Optimized avg: {total_opt/iterations*1000:.4f} ms")
    print(f"Improvement: {(total_orig - total_opt) / total_orig * 100:.2f}%")

if __name__ == "__main__":
    run()

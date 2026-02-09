from collections import Counter

ALPHABET = "abcdefghijklmnopqrstuvwxyzåäö"
N = len(ALPHABET)

char_to_int = {c: i for i, c in enumerate(ALPHABET)}
int_to_char = {i: c for i, c in enumerate(ALPHABET)}


def clean_text(text):
    return "".join(c for c in text.lower() if c in char_to_int)



def get_frequencies(text):
    text = clean_text(text)
    total = len(text)
    counts = Counter(text)
    return {c: counts.get(c, 0) / total for c in ALPHABET}



def index_of_coincidence(text):
    counts = Counter(text)
    n = len(text)
    if n < 2:
        return 0
    return sum(v * (v - 1) for v in counts.values()) / (n * (n - 1))


def guess_key_length(ciphertext, max_len=16):
    results = []
    for k in range(1, max_len + 1):
        parts = [ciphertext[i::k] for i in range(k)]
        ic = sum(index_of_coincidence(p) for p in parts) / k
        results.append((k, ic))
    results.sort(key=lambda x: -x[1])
    return results



def chi_squared(text, expected_freq):
    counts = Counter(text)
    total = len(text)
    chi = 0.0

    for c in ALPHABET:
        observed = counts.get(c, 0)
        expected = expected_freq[c] * total
        if expected > 0:
            chi += (observed - expected) ** 2 / expected

    return chi


def break_caesar(text, expected_freq):
    best_shift = 0
    best_score = float("inf")

    for shift in range(N):
        decrypted = "".join(
            int_to_char[(char_to_int[c] - shift) % N] for c in text
        )
        score = chi_squared(decrypted, expected_freq)

        if score < best_score:
            best_score = score
            best_shift = shift

    return best_shift



def decrypt(ciphertext, key):
    plaintext = []
    for i, c in enumerate(ciphertext):
        p = (char_to_int[c] - char_to_int[key[i % len(key)]]) % N
        plaintext.append(int_to_char[p])
    return "".join(plaintext)


def break_vigenere(ciphertext, expected_freq, max_key_len=16):
    results = []

    for key_len in range(1, max_key_len + 1):
        key = ""
        for i in range(key_len):
            segment = ciphertext[i::key_len]
            shift = break_caesar(segment, expected_freq)
            key += int_to_char[shift]

        plaintext = decrypt(ciphertext, key)
        score = chi_squared(plaintext, expected_freq)

        results.append((score, key, plaintext))

    results.sort(key=lambda x: x[0])
    return results

def break_vigenere_fixed_length(ciphertext, expected_freq, key_len):
    key = ""
    for i in range(key_len):
        segment = ciphertext[i::key_len]
        shift = break_caesar(segment, expected_freq)
        key += int_to_char[shift]

    plaintext = decrypt(ciphertext, key)
    return key, plaintext


if __name__ == "__main__":

    with open("ciphertext.txt", "r", encoding="utf-8") as f:
        ciphertext = clean_text(f.read())

    with open("swedish_reference.txt", "r", encoding="utf-8") as f:
        reference_text = f.read()

    expected_freq = get_frequencies(reference_text)

    print("=== Automatic candidates (top 5) ===")
    results = break_vigenere(ciphertext, expected_freq)

    for score, key, plaintext in results[:5]:
        print("\nCandidate key:", key)
        print("Score:", score)
        print("Plaintext preview:")
        print(plaintext[:200])

    print("\n=== Forced key length = 6 ===")
    key6, plaintext6 = break_vigenere_fixed_length(ciphertext, expected_freq, 6)
    print("Key:", key6)
    print("Plaintext:")
    print(plaintext6)



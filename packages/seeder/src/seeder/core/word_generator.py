#!/usr/bin/env python3
"""
Deterministic word generator for Seeder system.
Generates pronounceable words and dictionary words using seed-based randomness.

⚠️  IMPORTANT: This generates words for MEMORIZED PASSWORD COMPONENTS,
    NOT BIP-39 or SLIP-39 mnemonic words. BIP-39/SLIP-39 use standardized 2048-word
    dictionaries. This tool creates custom words for password construction.
"""

import hashlib

from .crypto import SeedCardCrypto

try:
    from wonderwords import RandomWord
    WONDERWORDS_AVAILABLE = True
except ImportError:
    WONDERWORDS_AVAILABLE = False


class WordGenerator:
    """Generates deterministic pronounceable words for memorized password components."""

    # Common English consonants and vowels for pronounceable words
    CONSONANTS = "bcdfghjklmnpqrstvwxyz"
    VOWELS = "aeiou"

    # Common word patterns for different lengths
    PATTERNS = {
        3: ["CVC"],  # Consonant-Vowel-Consonant
        4: ["CVCV", "CVCC"],
        5: ["CVCVC", "CCVCV", "CVCCC"],
        6: ["CVCVCV", "CCVCVC", "CVCVCC"],
        7: ["CVCVCVC", "CCVCVCV", "CVCVCCC"],
        8: ["CVCVCVCV", "CCVCVCVC", "CVCVCVCC"],
        9: ["CVCVCVCVC", "CCVCVCVCV"],
        10: ["CVCVCVCVCV", "CCVCVCVCVC"],
        11: ["CVCVCVCVCVC"],
        12: ["CVCVCVCVCVCV"]
    }

    @staticmethod
    def generate_word(seed_bytes: bytes, length: int, word_index: int = 0) -> str:
        """
        Generate a deterministic pronounceable word of specified length.

        Args:
            seed_bytes: 64-byte seed for deterministic generation
            length: Desired word length (3-12 characters)
            word_index: Index for generating multiple different words from same seed

        Returns:
            Pronounceable word of specified length

        Raises:
            ValueError: If length is not supported (3-12 chars)
        """
        if length < 3 or length > 12:
            raise ValueError(f"Word length must be 3-12 characters, got {length}")

        if length not in WordGenerator.PATTERNS:
            raise ValueError(f"No patterns available for length {length}")

        # Create unique context for this word generation
        context = f"WORD-{length}-{word_index}".encode()
        word_seed = hashlib.sha512(seed_bytes + context).digest()

        # Generate stream for letter selection
        stream = SeedCardCrypto.hkdf_like_stream(word_seed, b"LETTERS", length * 8)

        # Select pattern deterministically
        patterns = WordGenerator.PATTERNS[length]
        pattern_idx = stream[0] % len(patterns)
        pattern = patterns[pattern_idx]

        # Generate word following the pattern
        word = ""
        stream_pos = 1

        for char_type in pattern:
            if char_type == 'C':
                # Select consonant
                char_idx = stream[stream_pos] % len(WordGenerator.CONSONANTS)
                word += WordGenerator.CONSONANTS[char_idx]
            else:  # char_type == 'V'
                # Select vowel
                char_idx = stream[stream_pos] % len(WordGenerator.VOWELS)
                word += WordGenerator.VOWELS[char_idx]
            stream_pos += 1

        return word.capitalize()

    @staticmethod
    def generate_word_list(seed_bytes: bytes, length: int, count: int = 10) -> list[str]:
        """
        Generate multiple pronounceable words of specified length.

        Args:
            seed_bytes: 64-byte seed for deterministic generation
            length: Desired word length (3-12 characters)
            count: Number of words to generate

        Returns:
            List of pronounceable words
        """
        return [
            WordGenerator.generate_word(seed_bytes, length, i)
            for i in range(count)
        ]

    @staticmethod
    def get_supported_lengths() -> list[int]:
        """Get list of supported word lengths."""
        return sorted(WordGenerator.PATTERNS.keys())

    @staticmethod
    def calculate_word_entropy(length: int) -> float:
        """
        Calculate approximate entropy for a word of given length.

        Args:
            length: Word length in characters

        Returns:
            Estimated entropy in bits
        """
        if length < 3 or length > 12:
            return 0.0

        # Estimate based on pattern complexity and letter choices
        # This is approximate - actual entropy depends on pattern distribution
        consonant_choices = len(WordGenerator.CONSONANTS)  # 21
        vowel_choices = len(WordGenerator.VOWELS)  # 5

        # Rough estimate: alternating C/V pattern gives mixed entropy
        # Real calculation would need to consider all patterns and their probabilities
        avg_choices_per_char = (consonant_choices + vowel_choices) / 2  # ~13

        # Use log2 of approximate search space
        import math
        return length * math.log2(avg_choices_per_char)

    @staticmethod
    def get_pattern(word: str) -> str:
        """
        Get the consonant/vowel pattern for a word.

        Args:
            word: Word to analyze

        Returns:
            Pattern string (C=consonant, V=vowel)
        """
        pattern = ""
        for char in word.lower():
            if char in WordGenerator.VOWELS:
                pattern += "V"
            elif char in WordGenerator.CONSONANTS:
                pattern += "C"
            else:
                pattern += "?"  # For non-alphabetic characters
        return pattern


class DictionaryWordGenerator:
    """Generates deterministic dictionary words for memorized password components."""

    @staticmethod
    def is_available() -> bool:
        """Check if dictionary word generation is available."""
        return WONDERWORDS_AVAILABLE

    @staticmethod
    def generate_word(seed_bytes: bytes, word_index: int = 0,
                     min_length: int = 4, max_length: int = 8,
                     word_type: str = "common") -> str:
        """
        Generate a deterministic dictionary word.

        Args:
            seed_bytes: 64-byte seed for deterministic generation
            word_index: Index for generating multiple different words from same seed
            min_length: Minimum word length
            max_length: Maximum word length
            word_type: Word type filter ("common", "nouns", "verbs", "adjectives", "all")

        Returns:
            Dictionary word

        Raises:
            ImportError: If wonderwords library is not available
            ValueError: If invalid parameters
        """
        if not WONDERWORDS_AVAILABLE:
            raise ImportError("wonderwords library not available. Install with: pip install wonderwords")

        if min_length < 2 or max_length > 15 or min_length > max_length:
            raise ValueError("Invalid length parameters")

        # Create deterministic seed for this specific word
        word_seed = hashlib.sha512(seed_bytes + word_index.to_bytes(4, 'big')).digest()

        # Convert seed to integer for random state
        seed_int = int.from_bytes(word_seed[:4], 'big')

        # Get appropriate word list based on type
        from wonderwords import RandomWord
        r = RandomWord()

        if word_type == "common":
            # Use general word list for common words
            word_list = r.filter(word_min_length=min_length, word_max_length=max_length)
        elif word_type == "nouns":
            # Get noun list from wonderwords
            all_nouns = r.parts_of_speech.get('nouns', [])
            word_list = [word for word in all_nouns if min_length <= len(word) <= max_length]
        elif word_type == "verbs":
            # Get verb list from wonderwords
            all_verbs = r.parts_of_speech.get('verbs', [])
            word_list = [word for word in all_verbs if min_length <= len(word) <= max_length]
        elif word_type == "adjectives":
            # Get adjective list from wonderwords
            all_adjectives = r.parts_of_speech.get('adjectives', [])
            word_list = [word for word in all_adjectives if min_length <= len(word) <= max_length]
        elif word_type == "all":
            # Use general word list for all words
            word_list = r.filter(word_min_length=min_length, word_max_length=max_length)
        else:
            raise ValueError(f"Unsupported word type: {word_type}")

        if not word_list:
            # Fallback to generated words if no dictionary words found
            return f"word{seed_int % 10000:04d}"

        # Select word deterministically
        word_index_mod = seed_int % len(word_list)
        return word_list[word_index_mod]

    @staticmethod
    def generate_word_list(seed_bytes: bytes, count: int = 5,
                          min_length: int = 4, max_length: int = 8,
                          word_type: str = "common") -> list[str]:
        """
        Generate a list of deterministic dictionary words.

        Args:
            seed_bytes: 64-byte seed for deterministic generation
            count: Number of words to generate
            min_length: Minimum word length
            max_length: Maximum word length
            word_type: Word type filter

        Returns:
            List of dictionary words
        """
        if not WONDERWORDS_AVAILABLE:
            raise ImportError("wonderwords library not available")

        return [
            DictionaryWordGenerator.generate_word(
                seed_bytes, i, min_length, max_length, word_type
            )
            for i in range(count)
        ]

    @staticmethod
    def get_supported_types() -> list[str]:
        """Get list of supported word types."""
        return ["common", "nouns", "verbs", "adjectives", "all"]

    @staticmethod
    def calculate_word_entropy(min_length: int, max_length: int, word_type: str = "common") -> float:
        """
        Calculate approximate entropy for dictionary words.

        Args:
            min_length: Minimum word length
            max_length: Maximum word length
            word_type: Word type filter

        Returns:
            Estimated entropy in bits
        """
        # Rough estimates based on English dictionary sizes
        word_counts = {
            "common": 3000,      # Common words
            "nouns": 25000,      # Noun vocabulary
            "verbs": 8000,       # Verb vocabulary
            "adjectives": 15000, # Adjective vocabulary
            "all": 50000         # Large vocabulary
        }

        estimated_words = word_counts.get(word_type, 3000)

        # Adjust for length constraints (shorter words are more common)
        if max_length <= 5:
            estimated_words = int(estimated_words * 0.3)
        elif max_length <= 7:
            estimated_words = int(estimated_words * 0.6)

        import math
        return math.log2(max(estimated_words, 100))


def demo_word_generator():
    """Demonstration of both word generator functionalities."""
    from seed_sources import SeedSources

    print("🎲 Word Generator Demo\n")

    # Use simple seed for demo
    seed_bytes = SeedSources.simple_to_seed("WordDemo")

    # Pronounceable words demo
    print("🗣️  PRONOUNCEABLE WORDS")
    print("Supported lengths:", WordGenerator.get_supported_lengths())
    print()

    for length in [4, 6, 8]:
        print(f"📝 {length}-character pronounceable words:")
        words = WordGenerator.generate_word_list(seed_bytes, length, 5)
        entropy = WordGenerator.calculate_word_entropy(length)
        print(f"   Words: {', '.join(words)}")
        print(f"   Entropy: ~{entropy:.1f} bits")
        print()

    # Dictionary words demo
    print("📖 DICTIONARY WORDS")
    if DictionaryWordGenerator.is_available():
        print("Supported types:", DictionaryWordGenerator.get_supported_types())
        print()

        for word_type in ["common", "nouns", "adjectives"]:
            print(f"📝 {word_type.capitalize()} dictionary words (4-7 chars):")
            try:
                words = DictionaryWordGenerator.generate_word_list(
                    seed_bytes, 5, min_length=4, max_length=7, word_type=word_type
                )
                entropy = DictionaryWordGenerator.calculate_word_entropy(4, 7, word_type)
                print(f"   Words: {', '.join(words)}")
                print(f"   Entropy: ~{entropy:.1f} bits")
            except Exception as e:
                print(f"   Error: {e}")
            print()

        # Demonstrate different length ranges
        print("📝 Short dictionary words (3-5 chars):")
        try:
            short_words = DictionaryWordGenerator.generate_word_list(
                seed_bytes, 5, min_length=3, max_length=5, word_type="common"
            )
            print(f"   Words: {', '.join(short_words)}")
        except Exception as e:
            print(f"   Error: {e}")
        print()

        print("📝 Long dictionary words (6-10 chars):")
        try:
            long_words = DictionaryWordGenerator.generate_word_list(
                seed_bytes, 5, min_length=6, max_length=10, word_type="all"
            )
            print(f"   Words: {', '.join(long_words)}")
        except Exception as e:
            print(f"   Error: {e}")
        print()
    else:
        print("❌ Dictionary word generation not available")
        print("💡 Install wonderwords: pip install wonderwords")
        print()


if __name__ == "__main__":
    demo_word_generator()

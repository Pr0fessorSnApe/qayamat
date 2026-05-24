"""QAYAMAT — Reinforcement Learning Recon Agent
Q-learning agent that learns which recon sources yield the most findings for a given target profile.
"""

import json
import random
import sqlite3
from pathlib import Path
from typing import List, Dict, Any


class RLReconAgent:
    def __init__(
        self,
        state_size: int = 10,
        action_size: int = 20,
        learning_rate: float = 0.1,
        discount: float = 0.9,
        epsilon: float = 0.2,
    ):
        self.state_size = state_size
        self.action_size = action_size
        self.lr = learning_rate
        self.gamma = discount
        self.epsilon = epsilon
        self.db_path = "data/rl_recon.db"
        self._init_db()

    def _init_db(self) -> None:
        Path(self.db_path).parent.mkdir(exist_ok=True)
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                "CREATE TABLE IF NOT EXISTS q_table "
                "(state TEXT, action INTEGER, value REAL, PRIMARY KEY (state, action))"
            )

    def _state_key(self, features: Dict[str, Any]) -> str:
        return json.dumps(features, sort_keys=True)

    def _get_q(self, state: str, action: int) -> float:
        with sqlite3.connect(self.db_path) as conn:
            cur = conn.execute(
                "SELECT value FROM q_table WHERE state=? AND action=?", (state, action)
            )
            row = cur.fetchone()
        return row[0] if row else 0.0

    def _set_q(self, state: str, action: int, value: float) -> None:
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                "INSERT OR REPLACE INTO q_table (state, action, value) VALUES (?,?,?)",
                (state, action, value),
            )

    def get_action(self, state_features: Dict[str, Any], available_actions: List[int]) -> int:
        """Epsilon-greedy action selection."""
        if not available_actions:
            raise ValueError("available_actions must not be empty")
        if random.random() < self.epsilon:
            return random.choice(available_actions)
        state = self._state_key(state_features)
        q_vals = [(a, self._get_q(state, a)) for a in available_actions]
        max_q = max(q for _, q in q_vals)
        best = [a for a, q in q_vals if q == max_q]
        return random.choice(best)

    def update(
        self,
        state_features: Dict[str, Any],
        action: int,
        reward: float,
        next_state_features: Dict[str, Any],
        next_available_actions: List[int],
    ) -> None:
        """Q-learning update rule."""
        state = self._state_key(state_features)
        next_state = self._state_key(next_state_features)

        old_q = self._get_q(state, action)
        next_max = max(
            (self._get_q(next_state, a) for a in next_available_actions),
            default=0.0,
        )
        new_q = old_q + self.lr * (reward + self.gamma * next_max - old_q)
        self._set_q(state, action, new_q)

    def decay_epsilon(self, factor: float = 0.99) -> None:
        self.epsilon = max(0.01, self.epsilon * factor)

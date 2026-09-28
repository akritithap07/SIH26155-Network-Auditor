import json
from pathlib import Path
from typing import Any, Dict, List, Optional

from sentence_transformers import SentenceTransformer

from app.learning.store import LearningStore


DEFAULT_MODEL_NAME = "all-MiniLM-L6-v2"

DEFAULT_CORPUS_PATH = (
    Path(__file__).resolve().parents[2]
    / "data"
    / "learning_examples.json"
)


class SemanticMapper:
    """
    Semantic suggestion engine for unrecognized configuration lines.

    The mapper suggests candidate mappings. It does not make
    compliance decisions and does not automatically persist mappings.
    """

    def __init__(
        self,
        model_name: str = DEFAULT_MODEL_NAME,
        corpus_path: Optional[Path] = None,
        store: Optional[LearningStore] = None,
        model: Optional[Any] = None,
    ):
        self.model_name = model_name

        self.corpus_path = (
            Path(corpus_path)
            if corpus_path is not None
            else DEFAULT_CORPUS_PATH
        )

        self.store = (
            store
            if store is not None
            else LearningStore()
        )

        self.model = (
            model
            if model is not None
            else SentenceTransformer(model_name)
        )

        self.seed_examples = self._load_corpus()

        self._seed_embeddings = []

        if self.seed_examples:
            seed_texts = [
                self._embedding_text(example)
                for example in self.seed_examples
            ]

            self._seed_embeddings = (
                self._encode_many(seed_texts)
            )

    # ------------------------------------------------------------------
    # Corpus
    # ------------------------------------------------------------------

    def _load_corpus(self) -> List[Dict[str, Any]]:
        if not self.corpus_path.exists():
            raise FileNotFoundError(
                f"Learning corpus not found: "
                f"{self.corpus_path}"
            )

        with self.corpus_path.open(
            "r",
            encoding="utf-8",
        ) as corpus_file:
            data = json.load(corpus_file)

        if not isinstance(data, list):
            raise ValueError(
                "Learning corpus must contain a JSON list."
            )

        required_fields = {
            "vendor",
            "example",
            "control_id",
            "target_key",
            "description",
        }

        for index, example in enumerate(data):
            if not isinstance(example, dict):
                raise ValueError(
                    f"Corpus entry {index} must be an object."
                )

            missing = (
                required_fields
                - set(example.keys())
            )

            if missing:
                raise ValueError(
                    f"Corpus entry {index} is missing: "
                    f"{sorted(missing)}"
                )

        return data

    # ------------------------------------------------------------------
    # Text helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _normalize_text(
        text: str,
    ) -> str:
        return " ".join(
            text.strip().lower().split()
        )

    @staticmethod
    def _embedding_text(
        example: Dict[str, Any],
    ) -> str:
        return (
            f"{example['example']} "
            f"{example['description']}"
        )

    # ------------------------------------------------------------------
    # Embedding helpers
    # ------------------------------------------------------------------

    def _encode_one(
        self,
        text: str,
    ):
        """
        Encode exactly one piece of text and return a flat vector.

        This handles both:
            [dim]
        and:
            [[dim]]
        representations so tests and production models behave
        consistently.
        """

        encoded = self.model.encode(
            text,
            normalize_embeddings=True,
        )

        if hasattr(encoded, "tolist"):
            encoded = encoded.tolist()

        if (
            isinstance(encoded, list)
            and encoded
            and isinstance(encoded[0], list)
        ):
            encoded = encoded[0]

        if not isinstance(encoded, list):
            encoded = list(encoded)

        return encoded

    def _encode_many(
        self,
        texts: List[str],
    ):
        """
        Encode multiple texts into a list of flat vectors.
        """

        encoded = self.model.encode(
            texts,
            normalize_embeddings=True,
        )

        if hasattr(encoded, "tolist"):
            encoded = encoded.tolist()

        if not isinstance(encoded, list):
            encoded = list(encoded)

        normalized_vectors = []

        for vector in encoded:
            if hasattr(vector, "tolist"):
                vector = vector.tolist()

            if (
                isinstance(vector, list)
                and vector
                and isinstance(vector[0], list)
            ):
                vector = vector[0]

            normalized_vectors.append(
                list(vector)
            )

        return normalized_vectors

    @staticmethod
    def _dot_product(
        left,
        right,
    ) -> float:
        return sum(
            float(a) * float(b)
            for a, b in zip(left, right)
        )

    # ------------------------------------------------------------------
    # Confidence
    # ------------------------------------------------------------------

    @staticmethod
    def _confidence_band(
        score: float,
    ) -> str:
        if score >= 0.82:
            return "high"

        if score >= 0.65:
            return "medium"

        return "low"

    # ------------------------------------------------------------------
    # Suggestions
    # ------------------------------------------------------------------

    def suggest(
        self,
        vendor: str,
        source_text: str,
        top_k: int = 3,
    ) -> List[Dict[str, Any]]:
        if not isinstance(vendor, str):
            raise TypeError(
                "vendor must be a string"
            )

        if not isinstance(source_text, str):
            raise TypeError(
                "source_text must be a string"
            )

        if top_k < 1:
            raise ValueError(
                "top_k must be at least 1"
            )

        normalized_source = self._normalize_text(
            source_text
        )

        if not normalized_source:
            return []

        # --------------------------------------------------------------
        # 1. Previously learned exact mapping
        # --------------------------------------------------------------

        learned_mappings = (
            self.store.list_mappings(
                vendor=vendor
            )
        )

        exact_learned = [
            mapping
            for mapping in learned_mappings
            if self._normalize_text(
                str(mapping["source_text"])
            ) == normalized_source
        ]

        if exact_learned:
            return [
                {
                    "vendor": vendor,
                    "control_id": mapping["control_id"],
                    "target_key": mapping["target_key"],
                    "example": mapping["source_text"],
                    "description": (
                        mapping["rationale"]
                        or "Previously confirmed mapping."
                    ),
                    "score": 1.0,
                    "confidence_band": "high",
                    "match_source": "learned",
                    "learned": True,
                }
                for mapping in exact_learned[:top_k]
            ]

        # --------------------------------------------------------------
        # 2. Exact seed-corpus match
        # --------------------------------------------------------------

        exact_seed = []

        for example in self.seed_examples:
            if example["vendor"] != vendor:
                continue

            if (
                self._normalize_text(
                    str(example["example"])
                )
                == normalized_source
            ):
                exact_seed.append(
                    {
                        "vendor": vendor,
                        "control_id": example[
                            "control_id"
                        ],
                        "target_key": example[
                            "target_key"
                        ],
                        "example": example[
                            "example"
                        ],
                        "description": example[
                            "description"
                        ],
                        "score": 1.0,
                        "confidence_band": "high",
                        "match_source": "seed_exact",
                        "learned": False,
                    }
                )

        if exact_seed:
            return exact_seed[:top_k]

        # --------------------------------------------------------------
        # 3. Semantic matching against seed corpus
        # --------------------------------------------------------------

        query_embedding = self._encode_one(
            source_text
        )

        candidates: List[
            Dict[str, Any]
        ] = []

        for index, example in enumerate(
            self.seed_examples
        ):
            if example["vendor"] != vendor:
                continue

            score = self._dot_product(
                query_embedding,
                self._seed_embeddings[index],
            )

            score = float(score)

            candidates.append(
                {
                    "vendor": vendor,
                    "control_id": example[
                        "control_id"
                    ],
                    "target_key": example[
                        "target_key"
                    ],
                    "example": example[
                        "example"
                    ],
                    "description": example[
                        "description"
                    ],
                    "score": round(
                        score,
                        4,
                    ),
                    "confidence_band": (
                        self._confidence_band(
                            score
                        )
                    ),
                    "match_source": "seed",
                    "learned": False,
                }
            )

        # --------------------------------------------------------------
        # 4. Semantic matching against learned mappings
        # --------------------------------------------------------------

        learned_candidates = [
            mapping
            for mapping in learned_mappings
            if self._normalize_text(
                str(mapping["source_text"])
            ) != normalized_source
        ]

        if learned_candidates:
            learned_texts = [
                str(mapping["source_text"])
                for mapping in learned_candidates
            ]

            learned_embeddings = (
                self._encode_many(
                    learned_texts
                )
            )

            for index, mapping in enumerate(
                learned_candidates
            ):
                score = self._dot_product(
                    query_embedding,
                    learned_embeddings[index],
                )

                score = float(score)

                candidates.append(
                    {
                        "vendor": vendor,
                        "control_id": mapping[
                            "control_id"
                        ],
                        "target_key": mapping[
                            "target_key"
                        ],
                        "example": mapping[
                            "source_text"
                        ],
                        "description": (
                            mapping["rationale"]
                            or "Previously confirmed "
                            "mapping."
                        ),
                        "score": round(
                            score,
                            4,
                        ),
                        "confidence_band": (
                            self._confidence_band(
                                score
                            )
                        ),
                        "match_source": "learned",
                        "learned": True,
                    }
                )

        # --------------------------------------------------------------
        # 5. Deterministic ordering
        # --------------------------------------------------------------

        candidates.sort(
            key=lambda candidate: (
                -candidate["score"],
                candidate["control_id"],
                candidate["target_key"],
            )
        )

        # --------------------------------------------------------------
        # 6. Deduplicate control mappings
        # --------------------------------------------------------------

        deduplicated: List[
            Dict[str, Any]
        ] = []

        seen = set()

        for candidate in candidates:
            identity = (
                candidate["control_id"],
                candidate["target_key"],
            )

            if identity in seen:
                continue

            seen.add(identity)
            deduplicated.append(candidate)

            if len(deduplicated) >= top_k:
                break

        return deduplicated

    # ------------------------------------------------------------------
    # Human confirmation
    # ------------------------------------------------------------------

    def confirm(
        self,
        vendor: str,
        source_text: str,
        candidate: Dict[str, Any],
        confirmed_by: str = "human",
    ) -> Dict[str, object]:
        required_fields = {
            "control_id",
            "target_key",
            "score",
        }

        missing = (
            required_fields
            - set(candidate.keys())
        )

        if missing:
            raise ValueError(
                "Candidate is missing: "
                f"{sorted(missing)}"
            )

        return self.store.save_mapping(
            vendor=vendor,
            source_text=source_text,
            control_id=str(
                candidate["control_id"]
            ),
            target_key=str(
                candidate["target_key"]
            ),
            similarity_score=float(
                candidate["score"]
            ),
            rationale=str(
                candidate.get(
                    "description",
                    "Human-confirmed mapping.",
                )
            ),
            confirmed_by=confirmed_by,
        )
from app.learning.trainer import SemanticMapper


class FakeEmbeddingModel:
    def encode(
        self,
        texts,
        normalize_embeddings=True,
    ):
        if isinstance(texts, str):
            texts = [texts]

        vectors = []

        for text in texts:
            normalized = (
                text.lower()
            )

            vectors.append(
                [
                    1.0 if "ssh" in normalized else 0.0,
                    1.0 if "password" in normalized else 0.0,
                    1.0 if "telnet" in normalized else 0.0,
                    1.0 if "banner" in normalized else 0.0,
                    1.0 if "timeout" in normalized else 0.0,
                    1.0 if "access-class" in normalized else 0.0,
                    1.0 if "snmp" in normalized else 0.0,
                ]
            )

        return vectors


def test_semantic_mapper_returns_ranked_candidates(
    tmp_path,
):
    corpus_path = (
        tmp_path
        / "learning_examples.json"
    )

    corpus_path.write_text(
        """
[
  {
    "vendor": "cisco_ios",
    "example": "SSH version 2",
    "control_id": "CIS-NET-03",
    "target_key": "security.ssh_version",
    "description": "SSH protocol version 2"
  },
  {
    "vendor": "cisco_ios",
    "example": "service password-encryption",
    "control_id": "CIS-NET-05",
    "target_key": "security.password_encryption_enabled",
    "description": "Encrypt passwords"
  }
]
""",
        encoding="utf-8",
    )

    mapper = SemanticMapper(
        corpus_path=corpus_path,
        model=FakeEmbeddingModel(),
    )

    candidates = mapper.suggest(
        vendor="cisco_ios",
        source_text="configure SSH version 2",
        top_k=2,
    )

    assert len(candidates) == 2

    assert candidates[0]["control_id"] == (
        "CIS-NET-03"
    )

    assert (
        candidates[0]["match_source"]
        == "seed"
    )

    assert candidates[0]["learned"] is False
    assert candidates[0]["score"] > 0


def test_confirmed_mapping_is_reused_exactly(
    tmp_path,
):
    corpus_path = (
        tmp_path
        / "learning_examples.json"
    )

    corpus_path.write_text(
        """
[
  {
    "vendor": "cisco_ios",
    "example": "SSH version 2",
    "control_id": "CIS-NET-03",
    "target_key": "security.ssh_version",
    "description": "SSH protocol version 2"
  }
]
""",
        encoding="utf-8",
    )

    mapper = SemanticMapper(
        corpus_path=corpus_path,
        model=FakeEmbeddingModel(),
    )

    candidates = mapper.suggest(
        vendor="cisco_ios",
        source_text="ip ssh version 2",
        top_k=1,
    )

    confirmed = mapper.confirm(
        vendor="cisco_ios",
        source_text="ip ssh version 2",
        candidate=candidates[0],
    )

    assert confirmed["control_id"] == (
        "CIS-NET-03"
    )

    reused = mapper.suggest(
        vendor="cisco_ios",
        source_text="ip ssh version 2",
        top_k=1,
    )

    assert len(reused) == 1
    assert reused[0]["control_id"] == (
        "CIS-NET-03"
    )
    assert reused[0]["score"] == 1.0
    assert reused[0]["match_source"] == (
        "learned"
    )
    assert reused[0]["learned"] is True
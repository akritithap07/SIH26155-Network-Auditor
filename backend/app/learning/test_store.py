from app.learning.store import LearningStore


def test_learning_store_persists_confirmed_mapping(
    tmp_path,
):
    store = LearningStore(
        db_path=tmp_path / "test_learning.db"
    )

    saved = store.save_mapping(
        vendor="cisco_ios",
        source_text="ip ssh version 2",
        control_id="CIS-NET-03",
        target_key="security.ssh_version",
        similarity_score=0.91,
        rationale="Explicit SSH version 2 mapping.",
        confirmed_by="human",
    )

    assert saved["vendor"] == "cisco_ios"
    assert saved["control_id"] == "CIS-NET-03"
    assert saved["target_key"] == (
        "security.ssh_version"
    )

    mappings = store.find_by_source(
        vendor="cisco_ios",
        source_text="ip ssh version 2",
    )

    assert len(mappings) == 1
    assert mappings[0]["control_id"] == (
        "CIS-NET-03"
    )


def test_learning_store_updates_existing_mapping(
    tmp_path,
):
    store = LearningStore(
        db_path=tmp_path / "test_learning.db"
    )

    first = store.save_mapping(
        vendor="cisco_ios",
        source_text="service password-encryption",
        control_id="CIS-NET-05",
        target_key=(
            "security.password_encryption_enabled"
        ),
        similarity_score=0.80,
        rationale="Initial confirmation.",
    )

    second = store.save_mapping(
        vendor="cisco_ios",
        source_text="service password-encryption",
        control_id="CIS-NET-05",
        target_key=(
            "security.password_encryption_enabled"
        ),
        similarity_score=0.94,
        rationale="Updated confirmation.",
    )

    assert first["id"] == second["id"]
    assert second["similarity_score"] == 0.94

    mappings = store.find_by_source(
        vendor="cisco_ios",
        source_text="service password-encryption",
    )

    assert len(mappings) == 1
    assert mappings[0]["rationale"] == (
        "Updated confirmation."
    )
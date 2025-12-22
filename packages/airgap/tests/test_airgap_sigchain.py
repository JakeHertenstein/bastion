"""Tests for the airgap sigchain module."""

import tempfile
from pathlib import Path

import pytest
from airgap.sigchain import (
    EnclaveBatch,
    EnclaveEvent,
    EnclaveEventType,
    EnclaveSession,
)


class TestEnclaveEvent:
    """Tests for EnclaveEvent model."""

    def test_create_event(self):
        """Test creating an enclave event."""
        event = EnclaveEvent(
            event_type=EnclaveEventType.ENTROPY_COLLECTED,
            payload={"bits": 8192, "source": "infnoise"},
            local_seqno=1,
            session_id="test-session",
        )
        assert event.event_type == EnclaveEventType.ENTROPY_COLLECTED
        assert event.payload["bits"] == 8192
        assert len(event.payload_hash) == 64

    def test_event_hash_computed(self):
        """Test that payload hash is computed automatically."""
        event = EnclaveEvent(
            event_type=EnclaveEventType.KEY_GENERATED,
            payload={"key_type": "ed25519"},
            local_seqno=1,
            session_id="test",
        )
        assert event.payload_hash != ""
        assert len(event.payload_hash) == 64

    def test_event_summary(self):
        """Test event summary generation."""
        event = EnclaveEvent(
            event_type=EnclaveEventType.ENTROPY_COLLECTED,
            payload={"bits": 8192, "source": "infnoise"},
            local_seqno=1,
            session_id="test",
        )
        summary = event.get_summary()
        assert "8192" in summary
        assert "infnoise" in summary

    def test_key_generated_summary(self):
        """Test KEY_GENERATED event summary."""
        event = EnclaveEvent(
            event_type=EnclaveEventType.KEY_GENERATED,
            payload={"key_type": "ed25519"},
            local_seqno=1,
            session_id="test",
        )
        summary = event.get_summary()
        assert "ed25519" in summary

    def test_share_created_summary(self):
        """Test SHARE_CREATED event summary."""
        event = EnclaveEvent(
            event_type=EnclaveEventType.SHARE_CREATED,
            payload={"share_index": 2, "total_shares": 5},
            local_seqno=1,
            session_id="test",
        )
        summary = event.get_summary()
        assert "2" in summary
        assert "5" in summary


class TestEnclaveBatch:
    """Tests for EnclaveBatch model."""

    def test_create_batch(self):
        """Test creating an enclave batch."""
        batch = EnclaveBatch(session_id="test-session")
        assert batch.event_count == 0
        assert batch.session_id == "test-session"

    def test_add_event(self):
        """Test adding events to batch."""
        batch = EnclaveBatch(session_id="test-session")

        event = EnclaveEvent(
            event_type=EnclaveEventType.ENTROPY_COLLECTED,
            payload={"bits": 8192},
            local_seqno=1,
            session_id="test-session",
        )
        batch.add_event(event)

        assert batch.event_count == 1
        assert batch.first_local_seqno == 1
        assert batch.last_local_seqno == 1

    def test_add_multiple_events(self):
        """Test adding multiple events."""
        batch = EnclaveBatch(session_id="test-session")

        for i in range(5):
            event = EnclaveEvent(
                event_type=EnclaveEventType.ENTROPY_COLLECTED,
                payload={"bits": 1024 * (i + 1)},
                local_seqno=i + 1,
                session_id="test-session",
            )
            batch.add_event(event)

        assert batch.event_count == 5
        assert batch.first_local_seqno == 1
        assert batch.last_local_seqno == 5

    def test_compute_merkle_root(self):
        """Test merkle root computation."""
        batch = EnclaveBatch(session_id="test-session")

        for i in range(4):
            event = EnclaveEvent(
                event_type=EnclaveEventType.ENTROPY_COLLECTED,
                payload={"bits": 1024},
                local_seqno=i + 1,
                session_id="test-session",
            )
            batch.add_event(event)

        root = batch.compute_merkle_root()
        assert len(root) == 64

        # Same batch should produce same root
        root2 = batch.compute_merkle_root()
        assert root == root2

    def test_to_qr_data_and_back(self):
        """Test serializing batch for QR and deserializing."""
        batch = EnclaveBatch(session_id="test-session")

        for i in range(3):
            event = EnclaveEvent(
                event_type=EnclaveEventType.ENTROPY_COLLECTED,
                payload={"bits": 1024, "index": i},
                local_seqno=i + 1,
                session_id="test-session",
            )
            batch.add_event(event)

        qr_data = batch.to_qr_data()
        assert isinstance(qr_data, str)

        # Deserialize
        restored = EnclaveBatch.from_qr_data(qr_data)
        assert restored.session_id == batch.session_id
        assert restored.event_count == batch.event_count
        assert restored.merkle_root == batch.merkle_root

    def test_estimate_qr_size(self):
        """Test QR size estimation."""
        batch = EnclaveBatch(session_id="test-session")

        for i in range(3):
            event = EnclaveEvent(
                event_type=EnclaveEventType.ENTROPY_COLLECTED,
                payload={"bits": 1024},
                local_seqno=i + 1,
                session_id="test-session",
            )
            batch.add_event(event)

        size = batch.estimate_qr_size()
        assert size > 0
        assert size < 10000  # Should be reasonably small

    def test_can_fit_in_qr(self):
        """Test checking if batch fits in QR."""
        batch = EnclaveBatch(session_id="test-session")

        # Small batch should fit
        event = EnclaveEvent(
            event_type=EnclaveEventType.ENTROPY_COLLECTED,
            payload={"bits": 1024},
            local_seqno=1,
            session_id="test-session",
        )
        batch.add_event(event)

        assert batch.can_fit_in_qr(max_bytes=2048)


class TestEnclaveSession:
    """Tests for EnclaveSession manager."""

    def test_create_session(self):
        """Test creating a session."""
        with tempfile.TemporaryDirectory() as tmpdir:
            session = EnclaveSession(storage_path=Path(tmpdir))
            session_id = session.start()

            assert session_id != ""
            assert session.active is True

    def test_log_event(self):
        """Test logging events to session."""
        with tempfile.TemporaryDirectory() as tmpdir:
            session = EnclaveSession(storage_path=Path(tmpdir))
            session.start()

            event = session.log_event(
                EnclaveEventType.ENTROPY_COLLECTED,
                {"bits": 8192, "source": "infnoise"},
            )

            assert event.local_seqno == 2  # 1 is session start
            assert event.session_id == session.session_id

    def test_log_event_without_start_raises(self):
        """Test that logging without starting raises error."""
        with tempfile.TemporaryDirectory() as tmpdir:
            session = EnclaveSession(storage_path=Path(tmpdir))

            with pytest.raises(RuntimeError):
                session.log_event(
                    EnclaveEventType.ENTROPY_COLLECTED,
                    {"bits": 8192},
                )

    def test_end_session(self):
        """Test ending a session."""
        with tempfile.TemporaryDirectory() as tmpdir:
            session = EnclaveSession(storage_path=Path(tmpdir))
            session.start()

            session.log_event(
                EnclaveEventType.ENTROPY_COLLECTED,
                {"bits": 8192},
            )

            batch = session.end()

            assert session.active is False
            assert batch.event_count == 3  # start + entropy + end

    def test_export_batch(self):
        """Test exporting session as batch."""
        with tempfile.TemporaryDirectory() as tmpdir:
            session = EnclaveSession(storage_path=Path(tmpdir))
            session.start()

            for i in range(3):
                session.log_event(
                    EnclaveEventType.ENTROPY_COLLECTED,
                    {"bits": 1024 * (i + 1)},
                )

            batch = session.export_batch()

            assert batch.event_count == 4  # start + 3 entropy
            assert batch.session_id == session.session_id

    def test_split_into_qr_batches(self):
        """Test splitting large session into multiple QR batches."""
        with tempfile.TemporaryDirectory() as tmpdir:
            session = EnclaveSession(storage_path=Path(tmpdir))
            session.start()

            # Add many events to exceed QR capacity
            for i in range(50):
                session.log_event(
                    EnclaveEventType.ENTROPY_COLLECTED,
                    {"bits": 1024, "source": f"source_{i}", "extra_data": "x" * 50},
                )

            batches = session.split_into_qr_batches(max_bytes=1024)

            # Should be split into multiple batches
            assert len(batches) >= 1

            # All batches should fit in QR
            for batch in batches:
                assert batch.can_fit_in_qr(max_bytes=1024)

    def test_list_sessions(self):
        """Test listing available sessions."""
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir)

            # Create multiple sessions
            for i in range(3):
                session = EnclaveSession(storage_path=path)
                session.start()
                session.log_event(
                    EnclaveEventType.ENTROPY_COLLECTED,
                    {"bits": 1024},
                )

            sessions = EnclaveSession.list_sessions(storage_path=path)
            assert len(sessions) == 3

    def test_session_log_persisted(self):
        """Test that session log is persisted to disk."""
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir)

            session = EnclaveSession(storage_path=path)
            session_id = session.start()

            session.log_event(
                EnclaveEventType.ENTROPY_COLLECTED,
                {"bits": 8192},
            )

            # Check log file exists
            log_file = path / f"{session_id}.jsonl"
            assert log_file.exists()

            # Check contents
            lines = log_file.read_text().strip().split("\n")
            assert len(lines) == 2  # start + entropy


class TestEnclaveEventType:
    """Tests for EnclaveEventType constants."""

    def test_event_types(self):
        """Test event type values."""
        assert EnclaveEventType.KEY_GENERATED == "KEY_GENERATED"
        assert EnclaveEventType.SHARE_CREATED == "SHARE_CREATED"
        assert EnclaveEventType.BACKUP_VERIFIED == "BACKUP_VERIFIED"
        assert EnclaveEventType.ENTROPY_COLLECTED == "ENTROPY_COLLECTED"
        assert EnclaveEventType.SESSION_STARTED == "SESSION_STARTED"
        assert EnclaveEventType.SESSION_ENDED == "SESSION_ENDED"

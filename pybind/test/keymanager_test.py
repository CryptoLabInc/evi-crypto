from pathlib import Path
import json

import pytest

import evi


@pytest.fixture
def key_manager():
    return evi.KeyManager()

def test_wrap_and_unwrap_enc_key_round_trips_bytes(key_manager, key_dir, tmp_path):
    enc_key_path = Path(key_dir) / "EncKey.bin"
    wraped_path = tmp_path / "EncKey.json"
    restored_path = tmp_path / "EncKey.out"

    key_manager.wrap_enc_key("enc-key-id", str(enc_key_path), str(wraped_path))
    key_manager.unwrap_enc_key(str(wraped_path), str(restored_path))

    assert restored_path.read_bytes() == enc_key_path.read_bytes()


def test_keymanager_stream_roundtrip(ctx, tmp_path):
    contexts = [ctx]
    key_dir = tmp_path / "keys"
    key_dir.mkdir(parents=True, exist_ok=True)

    s_info = evi.SealInfo(evi.SealMode.NONE)
    keygen = evi.MultiKeyGenerator(contexts, str(key_dir), s_info)

    _, sec_blob, enc_blob, eval_blob = keygen.generate_keys_per_stream()

    key_id = "unit-test-vector-sk"

    manager = evi.KeyManager()

    wrapped_sec = manager.wrap_sec_key_bytes(key_id, sec_blob)
    wrapped_enc = manager.wrap_enc_key_bytes(key_id, enc_blob)
    wrapped_eval = manager.wrap_eval_key_bytes(key_id, eval_blob)

    unwrapped_sec = manager.unwrap_sec_key_bytes(wrapped_sec)
    unwrapped_enc = manager.unwrap_enc_key_bytes(wrapped_enc)
    unwrapped_eval = manager.unwrap_eval_key_bytes(wrapped_eval)

    assert unwrapped_sec == sec_blob
    assert unwrapped_enc == enc_blob
    assert unwrapped_eval == eval_blob


def test_revoke_and_destroy_pub_key_update_state_and_block_unwrap(key_manager, key_dir, tmp_path):
    enc_key_path = Path(key_dir) / "EncKey.bin"
    wrapped_path = tmp_path / "EncKey.lifecycle.json"
    restored_path = tmp_path / "EncKey.lifecycle.out"

    key_manager.wrap_enc_key("enc-lifecycle", str(enc_key_path), str(wrapped_path))
    key_manager.deactivate_pub_key(str(wrapped_path), "rotation complete")

    envelope = json.loads(wrapped_path.read_text())
    assert envelope["state"]["value"] == "deactivated"
    assert envelope["state"]["reason"] == "rotation complete"

    with pytest.raises(Exception, match="deactivated"):
        key_manager.unwrap_enc_key(str(wrapped_path), str(restored_path))

    key_manager.destroy_pub_key(str(wrapped_path), "retired")
    envelope = json.loads(wrapped_path.read_text())
    assert envelope["state"]["value"] == "destroyed"
    assert envelope["state"]["reason"] == "retired"

    with pytest.raises(Exception, match="destroyed"):
        key_manager.unwrap_enc_key(str(wrapped_path), str(restored_path))

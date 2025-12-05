from pathlib import Path

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

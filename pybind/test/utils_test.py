import json
import pytest

import evi


def test_encrypt_decrypt_metadata_roundtrip():
    metadata = "meta-unit-key|version=1|env=test|region=us|flags=1,0,1"
    key = bytes(range(32))
    aad = b"metadata-aad"

    encrypted = evi.utils.encrypt_metadata(metadata, key, aad)
    assert isinstance(encrypted, str)
    envelope = json.loads(encrypted)
    assert "iv" in envelope
    assert "tag" in envelope
    assert "encrypted_data" in envelope

    decrypted = evi.utils.decrypt_metadata(encrypted, key, aad)
    assert isinstance(decrypted, str)
    assert decrypted == metadata


def test_decrypt_metadata_with_wrong_key_fails():
    metadata = "k=v|n=7"
    key = bytes(range(32))
    wrong_key = bytes(range(1, 33))

    encrypted = evi.utils.encrypt_metadata(metadata, key)
    with pytest.raises(RuntimeError):
        evi.utils.decrypt_metadata(encrypted, wrong_key)

from app.hash import hash_password, verify_password


def test_hash_password_returns_bcrypt_hash():
    hashed = hash_password("s3cret!")
    assert hashed.startswith("$2")


def test_verify_password_round_trip():
    hashed = hash_password("s3cret!")
    assert verify_password("s3cret!", hashed) is True


def test_verify_password_rejects_wrong_password():
    hashed = hash_password("s3cret!")
    assert verify_password("wrong", hashed) is False


def test_hash_password_is_salted():
    assert hash_password("same") != hash_password("same")

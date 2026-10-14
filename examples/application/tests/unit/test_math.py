from app import add


def test_add():
    assert add(7, 5) == 12


def test_zero():
    assert add(0, 0) == 0

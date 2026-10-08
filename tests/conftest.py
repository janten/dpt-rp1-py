import pytest
import responses

from dptrp1.dptrp1 import DigitalPaper


@pytest.fixture
def device():
    client = DigitalPaper(addr="reader.example")
    # HTTP is intercepted by responses; no real reader or discovery is used.
    client.session.trust_env = False
    yield client
    client.session.close()


@pytest.fixture
def http():
    with responses.RequestsMock(assert_all_requests_are_fired=True) as mock:
        yield mock

from datetime import timedelta

import pytest

from acmems import config
from acmems import storages

from .helpers import gencsrpem, signcsr


### file storage

@pytest.fixture()
def file_storage(tmpdir):
    return storages.setup('file', (('directory', str(tmpdir)),))


class TestFileStorage():
    def test_error_without_directory(self):
        with pytest.raises(config.ConfigurationError) as e:
            storages.setup('file', ())
        assert 'directory' in str(e)

    def test_error_on_unknown_option(self, tmpdir):
        with pytest.raises(config.ConfigurationError) as e:
            storages.setup('file', (('directory', str(tmpdir)), ('unknonw', 'value')))
        assert 'unknonw' in str(e)

    def test_none_on_unknown_csr(self, file_storage, ckey):
        csr = gencsrpem(['test.example.org'], ckey)
        assert file_storage.from_cache(csr) is None

    def test_storages_placed_cert(self, file_storage, ckey):
        csr = gencsrpem(['test.example.org'], ckey)
        cert = signcsr(csr, ckey, timedelta(21, 0, 0))
        assert file_storage.add_to_cache(csr, cert) is True
        assert file_storage.from_cache(csr) == cert

    def test_remove_nearly_expired_cert(self, file_storage, ckey):
        csr = gencsrpem(['test.example.org'], ckey)
        cert = signcsr(csr, ckey, timedelta(9, 0, 0))
        assert file_storage.add_to_cache(csr, cert) is True
        assert file_storage.from_cache(csr) is None

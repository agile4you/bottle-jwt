# -*- coding: utf-8 -*-
"""Unit test fixtures for `bottle_jwt.backend` module
"""
from __future__ import unicode_literals
from __future__ import print_function


import pytest
import os
from  bottle_jwt.backends import (FileSystemBackend, BackendError)


@pytest.fixture(scope='module')
def file_backend():
    """Fixture for `bottle_jwt.backends.FilesystemBackend` class.
    """

    pwd = '/'.join(os.path.abspath(__file__).split('/')[:-1])

    db_file = pwd + '/mock_db.json'

    return FileSystemBackend(db_file)


def test_filesystembackend_lazy_load_data_prop(file_backend):
    """Test `bottle_jwt.backends.FilesystemBackend` data property.
    """

    assert file_backend.data[0]['user_id'] == 'pav'


def test_filesystembackend_lazy_load_fail(file_backend):
    """Test `bottle_jwt.backends.FilesystemBackend` data property.
    """

    backend_cls = file_backend.__class__

    with pytest.raises(BackendError):
        assert backend_cls('/sds').data


def test_filesystembackend_get_user_hit(file_backend):
    """Test `bottle_jwt.backends.FilesystemBackend.get_user` method.
    """

    assert file_backend.get_user('pav', '123')


def test_filesystembackend_get_user_not_found(file_backend):
    """Test `bottle_jwt.backends.FilesystemBackend.get_user` method not found.
    """

    assert not file_backend.get_user('pav', '12')

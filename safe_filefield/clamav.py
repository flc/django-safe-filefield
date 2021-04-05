import logging

from urllib.parse import urlparse

import clamd
from django.conf import settings
from django.utils.functional import SimpleLazyObject

from safe_filefield import default_settings


logger = logging.getLogger(__name__)


def get_scanner(socket, timeout=None):
    if socket.startswith('unix://'):
        return clamd.ClamdUnixSocket(socket[7:], timeout)
    elif socket.startswith('tcp://'):
        uri = urlparse(socket)

        return clamd.ClamdNetworkSocket(
            uri.hostname, uri.port or 3310, timeout
        )
    else:
        raise NotImplementedError(
            'Missed or unsupported ClamAV connection string schema. '
            'Only tcp:// or unix:// is allowed.'
        )


def _get_default_scanner():
    return get_scanner(
        getattr(settings, 'CLAMAV_SOCKET', default_settings.CLAMAV_SOCKET),
        getattr(settings, 'CLAMAV_TIMEOUT', default_settings.CLAMAV_TIMEOUT),
    )


scanner = SimpleLazyObject(_get_default_scanner)


def scan_file(f):
    _pos = f.tell()
    f.seek(0)
    try:
        status, virus_name = scanner.instream(f)['stream']
    except clamd.ConnectionError as e:
        logger.warning(str(e))
        return 'OK', ''
    f.seek(_pos)

    logger.debug('clamav result for file %s | status: %s', f, (status, virus_name))
    return status, virus_name

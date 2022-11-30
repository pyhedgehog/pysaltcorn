import typing as t
import logging
import pprint
import urllib.parse
import requests

log = logging.getLogger('saltcorn')
__version__ = "0.1.1"


class SaltcornError(RuntimeError):
    pass


class SaltcornServerError(SaltcornError):
    pass


class SaltcornRequestError(SaltcornError):
    pass


class SaltcornTransportError(SaltcornError):
    pass


class SaltcornAuthError(SaltcornError):
    pass


class SaltcornAuth(requests.auth.HTTPBasicAuth):
    def __call__(self, r: requests.PreparedRequest):
        if self.username == 'token':
            r.headers['Authorization'] = 'Bearer '+self.password
        elif self.username == 'jwt':
            r.headers['Authorization'] = 'JWT '+self.password
        else:
            super().__call__(r)
        r.headers['x-saltcorn-client'] = 'mobile-app'
        return r


class SaltcornClient:
    def __init__(self, url: str = 'http://127.0.0.1'):
        u = urllib.parse.urlsplit(url)
        host = ':'.join(str(s) for s in (u.hostname, u.port) if s)
        self.base_url = u._replace(netloc=host, fragment='', query='').geturl()
        self.auth = SaltcornAuth(u.username, u.password)
        self.session = requests.Session()

    def http_request(self, verb: str, path: str, null_404: bool = False, **kwargs):
        kwargs.setdefault('allow_redirects', False)
        r = None
        try:
            r = self.session.request(verb, urllib.parse.urljoin(self.base_url, path), **kwargs)
            if null_404 and r.status_code == 404:
                return None
            r.raise_for_status()
        except Exception as e:
            if r is not None and r.status_code == 401:
                raise SaltcornAuthError(str(e)) from e
            raise SaltcornTransportError(str(e)) from e
        return r

    def http_rest(self, verb: str, path: str, null_404: bool = False, **kwargs):
        r = self.http_request(verb, path, auth=self.auth, null_404=null_404, **kwargs)
        if null_404 and r is None:
            return r
        try:
            o = r.json()
        except Exception as e:
            log.debug('r: %s %s', r.status_code, r.reason)
            log.debug('r.headers: %s', pprint.pformat(r.headers))
            log.debug('r.text = %r', r.text)
            raise SaltcornServerError("Invalid server response: Can't parse JSON.") from e
        if not isinstance(o, dict):
            raise SaltcornServerError("Invalid server response: Must be JSON object.")
        if 'error' in o:
            raise SaltcornRequestError(o['error'])
        if 'success' not in o:
            raise SaltcornServerError("Invalid server response: No 'success' or 'error' keys.")
        return o['success']

    def tables_list(self):
        return self.http_rest('get', 'scapi/sc_tables')

    def row_list(self, table: str, /, **filters):
        return self.http_rest('get', 'api/'+table, params=filters)

    def row_insert(self, table: str, row: dict[str, t.Any]):
        return self.http_rest('post', 'api/'+table, json=row)

    def row_update(self, table: str, row: dict[str, t.Any]):
        return self.http_rest('post', 'api/%s/%s' % (table, row['id']), json=row)

    def row_delete(self, table: str, row_id: int):
        return self.http_rest('delete', 'api/%s/%d' % (table, row_id))

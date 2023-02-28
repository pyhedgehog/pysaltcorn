import logging
import os
import pprint
import re
import typing as t
import urllib.parse

import requests

log = logging.getLogger("saltcorn")
__version__ = "0.2.0"


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
    csrf = None
    password: str

    def __call__(self, r: requests.PreparedRequest):
        if self.csrf and r.method == "POST":
            r.headers["CSRF-Token"] = self.csrf
        if self.username == "token":
            r.headers["Authorization"] = "Bearer " + self.password
        elif self.username == "jwt":
            r.headers["Authorization"] = "JWT " + self.password
        else:
            super().__call__(r)
        return r


class SaltcornClient:
    def __init__(self, url: str = "", csrf_fixup: bool = False):
        u = urllib.parse.urlsplit(
            url or os.environ.get("SALTCORN_URL") or "https://saltcorn.com"
        )
        host = ":".join(str(s) for s in (u.hostname, u.port) if s)
        self.base_url = u._replace(netloc=host, fragment="", query="").geturl()
        self.csrf_fixup = csrf_fixup
        self.auth = SaltcornAuth(
            u.username or "token", u.password or os.environ.get("SALTCORN_TOKEN") or ""
        )
        self.session = requests.Session()

    @property
    def csrf(self):
        return self.auth.csrf

    @csrf.setter
    def csrf(self, value):
        self.auth.csrf = value
        return value

    def ensure_csrf(self):
        if not self.csrf_fixup:
            return
        if self.csrf:
            return
        r = self.session.get(urllib.parse.urljoin(self.base_url, "auth/login"))
        r.raise_for_status()
        m = re.search('<input type="hidden" name="_csrf" value="([^"]*)">', r.text)
        if m:
            self.csrf = m.group(1)

    def http_request(self, verb: str, path: str, null_404: bool = False, **kwargs):
        kwargs.setdefault("allow_redirects", False)
        verb = verb.upper()
        r = None
        try:
            if verb == "POST":
                self.ensure_csrf()
            r = self.session.request(
                verb, urllib.parse.urljoin(self.base_url, path), **kwargs
            )
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
            log.debug("r: %s %s", r.status_code, r.reason)
            log.debug("r.headers: %s", pprint.pformat(r.headers))
            log.debug("r.text = %r", r.text)
            raise SaltcornServerError(
                "Invalid server response: Can't parse JSON."
            ) from e
        if not isinstance(o, dict):
            raise SaltcornServerError(
                "Invalid server response: Must be JSON object (not %s)."
                % (type(o).__name__,)
            )
        if "error" in o:
            raise SaltcornRequestError(o["error"])
        if "success" not in o:
            raise SaltcornServerError(
                "Invalid server response: No 'success' or 'error' keys."
            )
        return o["success"]

    def tables_list(self):
        return self.http_rest("get", "scapi/sc_tables")

    def views_list(self):
        return self.http_rest("get", "scapi/sc_views")

    def pages_list(self):
        return self.http_rest("get", "scapi/sc_pages")

    def files_list(self):
        return self.http_rest("get", "scapi/sc_files")

    def triggers_list(self):
        return self.http_rest("get", "scapi/sc_triggers")

    def roles_list(self):
        return self.http_rest("get", "scapi/sc_roles")

    def tenants_list(self):
        return self.http_rest("get", "scapi/sc_tenants")

    def plugins_list(self):
        return self.http_rest("get", "scapi/sc_plugins")

    def config_get(self):
        return self.http_rest("get", "scapi/sc_config")

    def view_query(self, view: str, query: str, /, **args):
        """NB: Supported only for mobile clients. I.e. with JWT authorization."""
        return self.http_rest("post", "api/viewQuery/%s/%s" % (view, query), json=args)

    def action_call(self, action: str, /, **args):
        """NB: Supported only for mobile clients. I.e. with JWT authorization."""
        return self.http_rest("post", "api/action/" + action, json=args)

    def field_distinct_values(self, table: str, field: str, /):
        return self.http_rest("get", "api/%s/distinct/%s" % (table, field))

    def row_list(self, table: str, /, **filters):
        return self.http_rest("get", "api/" + table, params=filters)

    def row_insert(self, table: str, row: dict[str, t.Any]):
        return self.http_rest("post", "api/" + table, json=row)

    def row_update(self, table: str, row: dict[str, t.Any]):
        return self.http_rest("post", "api/%s/%s" % (table, row["id"]), json=row)

    def row_delete(self, table: str, row_id: int):
        return self.http_rest("delete", "api/%s/%d" % (table, row_id))

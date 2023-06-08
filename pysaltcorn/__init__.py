import logging
import os
import pprint
import re
import typing as t
import urllib.parse

import requests

from .support import bool_opt

try:
    from cgi import parse_header
except ImportError:
    # Future support: https://peps.python.org/pep-0594/#cgi
    from .support import parse_header  # type: ignore[assignment]


log = logging.getLogger("saltcorn")
__version__ = "0.3.1"
KindType = t.Literal["session", "token", "jwt", "basic", "public"]
FileDefType = str | t.IO | tuple[str, str | t.IO]
FilesType = dict[str, FileDefType] | t.Sequence[tuple[str, FileDefType]]


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
    _csrf: str | None = None
    username: str
    password: str
    alterego: dict[KindType, "SaltcornAuth"]

    def __init__(self, username: str | None, password: str | None):
        self.alterego = {}
        super().__init__(username or "", password or "")
        self.alterego[self.kind] = self

    def __call__(self, r: requests.PreparedRequest) -> requests.PreparedRequest:
        if self._csrf and r.method == "POST":
            r.headers["CSRF-Token"] = self._csrf
        if self.username == "cookie":
            log.warn("SaltcornAuth: Cookie: %r", r.headers["Cookie"])
            assert r.headers["Cookie"]
        elif self.username == "token":
            r.headers["Authorization"] = "Bearer " + self.password
        elif self.username == "jwt":
            r.headers["Authorization"] = "JWT " + self.password
        elif self.username:
            super().__call__(r)
        return r

    @property
    def csrf(self) -> str | None:
        return self._csrf

    @csrf.setter
    def csrf(self, newval: str | None):
        self._csrf = newval
        for res in self.alterego.values():
            res._csrf = newval

    def is_basic(self) -> bool:
        return bool(self.username) and self.username not in ("session", "token", "jwt")

    @property
    def kind(self) -> KindType:
        if bool(self.username) and self.username in ("session", "token", "jwt"):
            return self.username  # type: ignore[return-value]
        # if self.username and "@" in self.username:
        #     return "email"
        if not self.username:
            return "public"
        return "basic"

    def replace(
        self, username: t.Union["SaltcornAuth", str, None], password: str | None = None
    ) -> "SaltcornAuth":
        res = None
        if isinstance(username, SaltcornAuth):
            assert not password, "Usage error"
            res = username
            username = res.username
            password = res.password
            if res.alterego is not self.alterego:
                res = None
        if res is None:
            res = object.__new__(SaltcornAuth)
            res._csrf = self._csrf
            res.alterego = self.alterego
            res.username = username or ""
            res.password = password or ""
        if res.kind in self.alterego:
            res = self.alterego[res.kind]
        res.username = self.username
        res.password = self.password
        self.alterego[res.kind] = res
        self.username = username or ""
        self.password = password or ""
        self.alterego[self.kind] = self
        assert all(
            res.kind == kind for kind, res in self.alterego.items()
        ), "Internal error"
        return self

    def as_dict(self) -> dict[KindType, tuple[str, str]]:
        return {k: (o.username, o.password) for k, o in self.alterego.items()}

    def pprint(self):
        print(
            "\n".join(
                ":".join(
                    filter(
                        None,
                        [k, " " + o.username, o.password, "*" if o is self else None],
                    )
                )
                for k, o in self.alterego.items()
            )
        )

    def has_kind(self, key: KindType) -> bool:
        return key == "public" or key in self.alterego or key == self.kind

    def get_kind(self, *keys: KindType) -> "SaltcornAuth":
        last = len(keys) - 1
        res = None
        for i, key in enumerate(keys):
            if key not in self.alterego:
                if key == self.kind:
                    self.alterego[key] = self
                elif key == "public":
                    res = object.__new__(SaltcornAuth)
                    res._csrf = self._csrf
                    res.alterego = self.alterego
                    res.username = res.password = ""
                    self.alterego[key] = res
                elif i < last:
                    continue
            res = self.alterego[key]
        assert all(
            res.kind == kind for kind, res in self.alterego.items()
        ), "Internal error"
        # Must throw KeyError on last iteration of loop
        assert res, "Internal error"
        return res

    def pop_kind(self, key: KindType) -> "SaltcornAuth":
        assert (
            any(k != key for k in self.alterego.keys()) and key != "public"
        ), "No auths available to revert to"
        if key == self.kind:
            res = self.alterego[next(iter(k for k in self.alterego.keys() if k != key))]
            self.replace(res)
        assert key != self.kind, "Internal error"
        res = self.alterego.pop(key)
        res.alterego = {key: res}
        return res


class SaltcornClient:
    def __init__(
        self, url: str = "", csrf_fixup: bool | None = None, tenant: str | None = None
    ):
        u = urllib.parse.urlsplit(
            url or os.environ.get("SALTCORN_URL") or "https://saltcorn.com"
        )
        fraginfo = urllib.parse.parse_qs(u.fragment)
        host = ":".join(str(s) for s in (u.hostname, u.port) if s)
        self.base_url = u._replace(netloc=host, fragment="", query="").geturl()
        if csrf_fixup is None:
            csrf_fixup = bool_opt(fraginfo.get("csrf_fixup", ["False"])[0])
        self.csrf_fixup = csrf_fixup
        self.auth = SaltcornAuth(
            urllib.parse.unquote(u.username or "token"),
            urllib.parse.unquote(u.password)
            if u.password
            else os.environ.get("SALTCORN_TOKEN") or "",
        )
        self.session = requests.Session()
        fragtenant = fraginfo.get("tenant", [""])[0]
        tenant = tenant or os.environ.get("SALTCORN_TENANT") or fragtenant
        if not tenant and u.hostname and "." in u.hostname:
            tenant = u.hostname.split(".")[0]
        self.saltcorn_app = tenant or "public"

    @property
    def saltcorn_app(self):
        return self.session.headers.get("x-saltcorn-app")

    @saltcorn_app.setter
    def saltcorn_app(self, value: str):
        self.session.headers["x-saltcorn-app"] = value

    @property
    def csrf(self):
        return self.auth.csrf

    @csrf.setter
    def csrf(self, value: str | None):
        self.auth.csrf = value
        return value

    def _parse_csrf(self, reqtext: str):
        m = re.search('<input type="hidden" name="_csrf" value="([^"]*)">', reqtext)
        if m:
            return m.group(1)
        return None

    def _ensure_csrf(self):
        if self.csrf:
            return self.csrf
        r = self.session.get(urllib.parse.urljoin(self.base_url, "auth/login"))
        r.raise_for_status()
        self.csrf = self._parse_csrf(r.text) or self.csrf
        return self.csrf

    def _http_path(self, path: str):
        return urllib.parse.urljoin(self.base_url, path)

    def _http_request(
        self,
        verb: str,
        path: str,
        return_any_json: bool = False,
        null_404: bool = False,
        **kwargs,
    ):
        kwargs.setdefault("allow_redirects", False)
        verb = verb.upper()
        r = None
        try:
            if verb == "POST" and self.csrf_fixup:
                self._ensure_csrf()
            r = self.session.request(verb, self._http_path(path), **kwargs)
            if null_404 and r.status_code == 404:
                return None
            if (
                return_any_json
                and parse_header(r.headers["content-type"])[0] == "application/json"
            ):
                return r
            r.raise_for_status()
        except Exception as e:
            if r is not None and r.status_code == 401:
                raise SaltcornAuthError(str(e)) from e
            raise SaltcornTransportError(str(e)) from e
        return r

    def _http_rest(
        self,
        verb: str,
        path: str,
        return_whole_json: bool = False,
        return_unparsed_json: bool = False,
        null_404: bool = False,
        **kwargs,
    ):
        kwargs.setdefault("auth", self.auth)
        r = self._http_request(
            verb,
            path,
            return_any_json=return_unparsed_json or return_whole_json,
            null_404=null_404,
            **kwargs,
        )
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
        if return_unparsed_json:
            return o
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
        if return_whole_json:
            return o
        return o["success"]

    def _prepare_email_auth(
        self, email: str | None = None, password: str | None = None
    ):
        orig_auth = self.auth
        if self.auth.has_kind("basic"):
            orig_auth = self.auth.get_kind("basic")
        if email is None:
            assert orig_auth.kind == "basic", "Username/password not available"
            email, password = orig_auth.username, orig_auth.password
        else:
            if (email, password) != (orig_auth.username, orig_auth.password):
                # self.auth_history.push(self.aoth)
                self.auth = SaltcornAuth(email, password)
            else:
                self.auth.replace(email, password)
            assert (
                self.auth.kind == "basic"
            ), "Username/password passed in incorrect format"
        return email, password

    def login_session(
        self, email: str | None = None, password: str | None = None, **args
    ):
        email, password = self._prepare_email_auth(email, password)
        # _ensure_csrf must be after _prepare_email_auth as it may replace auth object
        self._ensure_csrf()
        r = self._http_request(
            "post",
            "auth/login",
            auth=None,
            return_any_json=True,
            data=dict(_csrf=self.csrf, email=email, password=password or "", **args),
        )
        m = re.search('<div id="alerts-area">(.*?)</div>', r.text, re.S)
        if m:
            raise SaltcornAuthError(re.sub("<[^>]*>", "", m.group(1)).strip())
        # print(dict(r.cookies.items()))
        assert "loggedin" in r.cookies
        self.auth.replace("session", r.cookies["connect.sid"])
        self.csrf = None  # force refresh of CSRF-Token
        return r.cookies["connect.sid"]

    def login_jwt(self, email: str | None = None, password: str | None = None, **args):
        email, password = self._prepare_email_auth(email, password)
        o = self._http_rest(
            "get",
            "auth/login-with/jwt",
            auth=None,
            return_unparsed_json=True,
            params=dict(email=email, password=password or "", **args),
        )
        assert isinstance(o, str) and len(o) > 20
        self.auth.replace("jwt", o)
        return o

    def auth_get_token(self):
        r = self._http_request(
            "get",
            "auth/settings",
            auth=self.auth,
            return_any_json=True,
        )
        m = re.search(
            '<div class="card(.*?)<form action="/auth/gen-api-token"', r.text, re.S
        )
        if not m:
            return None
        m = re.search("<code>([0-9a-z-]*)</code>", m.group(1), re.S)
        if not m:
            return None
        return m.group(1)

    def auth_gen_token(self):
        r = self._http_request(
            "post",
            "auth/gen-api-token",
            auth=self.auth,
            return_any_json=True,
        )
        assert (
            r.is_redirect
            and r.headers["location"]
            and r.headers["location"].startswith("/auth/settings")
        )
        token = self.auth_get_token()
        assert token
        return token

    def login_token(
        self, email: str | None = None, password: str | None = None, **args
    ):
        # if not self.csrf:
        #    self._ensure_csrf()
        if self.auth.has_kind("token"):
            self.auth.replace(self.auth.get_kind("token"))
            return self.auth.password
        if not self.auth.has_kind("session"):
            self.login_session(email, password, **args)
        self._ensure_login("session")
        token = self.auth_get_token()
        if not token:
            token = self.auth_gen_token()
        self.auth.replace("token", token)
        return token

    def _ensure_login(self, *kinds: KindType):
        for kind in kinds:
            if self.auth.has_kind(kind):
                if kind != self.auth.kind:
                    self.auth.replace(self.auth.get_kind(kind))
                return self.auth
            if kind == "token" and (
                self.auth.has_kind("basic") or self.auth.has_kind("session")
            ):
                self.login_token()
                return self.auth
            if kind == "jwt" and self.auth.has_kind("basic"):
                self.login_jwt()
                return self.auth
            if kind == "session" and self.auth.has_kind("basic"):
                self.login_jwt()
                return self.auth
        raise SaltcornAuthError("Can't find login kind %s", ",".join(kinds))

    def tables_list(self):
        return self._http_rest("get", "scapi/sc_tables")

    def views_list(self):
        return self._http_rest("get", "scapi/sc_views")

    def pages_list(self):
        return self._http_rest("get", "scapi/sc_pages")

    def files_list(self):
        return self._http_rest("get", "scapi/sc_files")

    def triggers_list(self):
        return self._http_rest("get", "scapi/sc_triggers")

    def roles_list(self):
        return self._http_rest("get", "scapi/sc_roles")

    def tenants_list(self):
        return self._http_rest("get", "scapi/sc_tenants")

    def plugins_list(self):
        return self._http_rest("get", "scapi/sc_plugins")

    def config_get(self):
        return self._http_rest("get", "scapi/sc_config")

    def files_upload(self, files: FilesType, folder: str = "/"):
        self._ensure_csrf()
        # self._ensure_login("session")
        if hasattr(files, "items"):
            files = files.items()  # type: ignore[assignment]
        r = self._http_request(
            "post",
            "files/upload",
            auth=self.auth,
            return_any_json=True,
            data=dict(_csrf=self.csrf, folder=folder),
            files=[  # type: ignore[misc]
                ("file", (v if isinstance(v, (list, tuple)) else [fn, v]))
                for fn, v in files
            ],  # +[('_csrf', io.StringIO(self.csrf)), ['folder', io.StringIO(folder)]],
            allow_redirects=False,
        )
        assert (
            r.is_redirect
            and r.headers["location"]
            and r.headers["location"].startswith("/files?")
        )
        return True

    def file_setrole(self, filename: str, role: int):
        if filename[:1] != "/":
            filename = "/" + filename
        self._ensure_csrf()
        # self._ensure_login("session")
        r = self._http_request(
            "post",
            "files/setrole" + filename,
            auth=self.auth,
            return_any_json=True,
            json=dict(_csrf=self.csrf, role=role),
            allow_redirects=False,
        )
        assert (
            r.is_redirect
            and r.headers["location"]
            and r.headers["location"].startswith("/files?")
        )
        return True

    def file_delete(self, filename: str):
        if filename[:1] != "/":
            filename = "/" + filename
        self._ensure_csrf()
        # self._ensure_login("session")
        r = self._http_request(
            "post",
            "files/delete" + filename,
            auth=self.auth,
            return_any_json=True,
            json=dict(_csrf=self.csrf),
            allow_redirects=False,
        )
        assert (
            r.is_redirect
            and r.headers["location"]
            and r.headers["location"].startswith("/files?")
        )
        return True

    def file_link(self, filename: str):
        return self._http_path("files/serve/" + filename.lstrip("/"))

    def file_request(self, filename: str):
        return self._http_request("get", self.file_link(filename), auth=self.auth)

    def file_get(self, filename: str):
        return self.file_request(filename).text

    def view_query(self, view: str, query: str, /, **args):
        """NB: Supported only for mobile clients. I.e. with JWT authorization."""
        # self._ensure_login("jwt")
        return self._http_rest(
            "post",
            "api/viewQuery/%s/%s" % (view, query),
            return_whole_json=True,
            json=args,
        )

    def action_call(self, action: str, /, **args):
        o = self._http_rest(
            "post", "api/action/" + action, return_whole_json=True, json=args
        )
        if o["success"] is not True:
            # if o["success"] is not True:
            raise SaltcornServerError("Expected success=true got %r" % (o["success"],))
        return o.get("data")

    def field_distinct_values(self, table: str, field: str, /, **opts):
        return self._http_rest("get", "api/%s/distinct/%s" % (table, field), **opts)

    def row_list(self, table: str, /, **filters):
        return self._http_rest("get", "api/" + table, params=filters)

    def row_insert(self, table: str, row: dict[str, t.Any]):
        return self._http_rest("post", "api/" + table, json=row)

    def row_update(self, table: str, row: dict[str, t.Any]):
        return self._http_rest("post", "api/%s/%s" % (table, row["id"]), json=row)

    def row_delete(self, table: str, row_id: int):
        return self._http_rest("delete", "api/%s/%d" % (table, row_id))

# PySaltcorn

This is python client interface for [Saltcorn](https://github.com/saltcorn/saltcorn/) REST API.

## Installation

```console
$ pip3 install pysaltcorn==0.3.1
```

## Usage

```python
>>> import io, pysaltcorn; from pprint import pp
>>> cl = pysaltcorn.SaltcornClient("https://url-encoded-email:password@tenant.saltcorn.com")
>>> cl.login_session()
>>> cl.files_upload({'filename.txt': io.StringIO('file content\n')}, '/foldername/')
True
>>> pp(cl.files_list())
[{'filename': 'foldername',
  'location': '/root/.local/share/saltcorn/netbox/foldername',
  'uploaded_at': '2023-06-08T12:20:25.323Z',
  'size_kb': 4,
  'user_id': None,
  'mime_super': '',
  'mime_sub': '',
  'min_role_read': 10,
  's3_store': False,
  'isDirectory': True}]
```

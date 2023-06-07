from typing import Callable

parse_header: Callable[[str], tuple[str, dict[str, str]]]
try:
    from werkzeug.http import parse_options_header

    def parse_header(line):
        return parse_options_header(line)

except ImportError:
    from email.message import Message

    def parse_header(line):
        if ";" not in line:
            return line, {}
        msg = Message()
        msg["content-type"] = line
        (data, dummy), *params = msg.get_params()
        return data, dict(params)


def bool_opt(optval: str | None) -> bool:
    return str(optval).lower().strip() not in ("0", "no", "nope", "false")

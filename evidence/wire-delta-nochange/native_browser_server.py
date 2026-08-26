import asyncio
import base64
import os

import cbor2

from aioquic.asyncio import (
    QuicConnectionProtocol,
    serve,
)

from aioquic.h3.connection import (
    H3_ALPN,
    H3Connection,
)

from aioquic.h3.events import (
    DataReceived,
    HeadersReceived,
)

from aioquic.quic.configuration import (
    QuicConfiguration,
)

from aioquic.quic.events import (
    HandshakeCompleted,
    ProtocolNegotiated,
)


SNAPSHOT = open(
    "/work/vectors/fullstack-snapshot.cose",
    "rb",
).read()

DELTA = open(
    "/work/vectors/fullstack-delta.cose",
    "rb",
).read()

SNAPSHOT_VALUE = (
    b":"
    + base64.b64encode(SNAPSHOT)
    + b":"
)

DELTA_VALUE = (
    b":"
    + base64.b64encode(DELTA)
    + b":"
)

PHASE = os.environ.get("NATIVE_PHASE", "pre")

PROTOCOL_COUNT = 0
HANDSHAKE_COUNT = 0

APP_PROTOCOL = None
APP_STREAMS = []
APP_PATHS = []


def cursor_description(cursor):
    if cursor is None:
        return "cursor_scopes=none cursor_gen=none"

    try:
        if not (
            cursor.startswith(b":")
            and cursor.endswith(b":")
        ):
            return (
                "cursor_scopes=parsefail "
                "cursor_gen=parsefail"
            )

        raw = base64.b64decode(
            cursor[1:-1],
            validate=True,
        )

        obj = cbor2.loads(raw)

        scopes = obj.get(2, [])

        if not scopes:
            return (
                f"cursor_raw_bytes={len(raw)} "
                "cursor_scopes=0 cursor_gen=none"
            )

        gen = scopes[0].get(2)

        return (
            f"cursor_raw_bytes={len(raw)} "
            f"cursor_scopes={len(scopes)} "
            f"cursor_gen={gen}"
        )

    except Exception as exc:
        return (
            "cursor_scopes=parsefail "
            f"cursor_gen=parsefail error={exc!r}"
        )


class BrowserServerProtocol(
    QuicConnectionProtocol
):
    def __init__(self, *args, **kwargs):
        global PROTOCOL_COUNT

        super().__init__(
            *args,
            **kwargs,
        )

        PROTOCOL_COUNT += 1
        self.protocol_number = PROTOCOL_COUNT
        self.http = None
        self.requests = {}

        print(
            "QUIC_PROTOCOL_CREATED "
            f"number={self.protocol_number}",
            flush=True,
        )

    def quic_event_received(
        self,
        event,
    ):
        global HANDSHAKE_COUNT

        if isinstance(
            event,
            ProtocolNegotiated,
        ):
            if event.alpn_protocol not in H3_ALPN:
                raise RuntimeError(
                    "HTTP3_ALPN_NOT_NEGOTIATED"
                )

            self.http = H3Connection(
                self._quic
            )

            print(
                "PROTOCOL_NEGOTIATED "
                f"protocol={self.protocol_number} "
                f"alpn={event.alpn_protocol}",
                flush=True,
            )

        if isinstance(
            event,
            HandshakeCompleted,
        ):
            HANDSHAKE_COUNT += 1

            print(
                "QUIC_HANDSHAKE_COMPLETED "
                f"protocol={self.protocol_number} "
                f"total={HANDSHAKE_COUNT}",
                flush=True,
            )

        if self.http is not None:
            for http_event in \
                    self.http.handle_event(
                        event
                    ):
                self.http_event_received(
                    http_event
                )

    def http_event_received(
        self,
        event,
    ):
        sid = event.stream_id

        if isinstance(
            event,
            HeadersReceived,
        ):
            self.requests[sid] = {
                "headers":
                    dict(event.headers),
                "body":
                    bytearray(),
            }

            if event.stream_ended:
                self.respond(sid)

        elif isinstance(
            event,
            DataReceived,
        ):
            req = self.requests.setdefault(
                sid,
                {
                    "headers": {},
                    "body": bytearray(),
                },
            )

            req["body"].extend(
                event.data
            )

            if event.stream_ended:
                self.respond(sid)

    def respond(
        self,
        stream_id,
    ):
        global APP_PROTOCOL
        global APP_STREAMS
        global APP_PATHS

        req = self.requests.get(
            stream_id,
            {},
        )

        headers = req.get(
            "headers",
            {},
        )

        path = headers.get(
            b":path",
            b"",
        ).decode(
            errors="replace"
        )

        cursor = headers.get(
            b"dns-freshness-cursor"
        )

        is_app = path in (
            "/app/1",
            "/app/2",
            "/app/3",
        )

        if is_app:
            print(
                "BROWSER_REQUEST "
                f"protocol={self.protocol_number} "
                f"stream={stream_id} "
                f"path={path} "
                f"cursor={cursor} "
                f"{cursor_description(cursor)}",
                flush=True,
            )

            if APP_PROTOCOL is None:
                APP_PROTOCOL = \
                    self.protocol_number

            if APP_PROTOCOL != \
                    self.protocol_number:
                print(
                    "FAIL: APP_REQUEST_MOVED_"
                    "TO_DIFFERENT_QUIC_CONNECTION",
                    flush=True,
                )

            APP_STREAMS.append(
                stream_id
            )

            APP_PATHS.append(
                path
            )

        if is_app:
            body = (
                "<!doctype html>"
                "<html><head>"
                "<link rel='icon' href='data:,'>"
                "</head><body>"
                + path
                + "</body></html>"
            ).encode()

            status = b"200"
        else:
            body = b""
            status = b"204"

        response_headers = [
            (
                b":status",
                status,
            ),
            (
                b"content-type",
                b"text/html",
            ),
            (
                b"cache-control",
                b"no-store",
            ),
            (
                b"content-length",
                str(len(body)).encode(),
            ),
        ]

        if path == "/app/1":
            response_headers.append(
                (
                    b"dns-freshness-object",
                    SNAPSHOT_VALUE,
                )
            )

            print(
                "FRESHNESS_SNAPSHOT_ATTACHED "
                f"protocol={self.protocol_number} "
                f"stream={stream_id} "
                f"bytes={len(SNAPSHOT)}",
                flush=True,
            )

        elif path == "/app/2":
            if APP_PATHS[:2] != [
                "/app/1",
                "/app/2",
            ]:
                raise RuntimeError(
                    "APP_SEQUENCE_INVALID"
                )

            response_headers.append(
                (
                    b"dns-freshness-object",
                    DELTA_VALUE,
                )
            )

            print(
                "FRESHNESS_DELTA_ATTACHED "
                f"protocol={self.protocol_number} "
                f"stream={stream_id} "
                f"bytes={len(DELTA)}",
                flush=True,
            )

        self.http.send_headers(
            stream_id=stream_id,
            headers=response_headers,
        )

        self.http.send_data(
            stream_id=stream_id,
            data=body,
            end_stream=True,
        )

        self.transmit()

        if path == "/app/2" and PHASE == "pre":
            print(
                "NATIVE_PRE_61_CONNECTION_CLOSE_SCHEDULED=PASS",
                flush=True,
            )
            asyncio.get_running_loop().call_later(
                0.5,
                self.close,
            )

        if path == "/app/3" and PHASE == "post":
            if APP_PATHS != ["/app/3"]:
                raise RuntimeError(
                    "POST_SWITCH_APP3_SEQUENCE_INVALID"
                )

            print(
                "NATIVE_POST_12_REQUEST3=PASS "
                f"protocol={self.protocol_number} "
                f"stream={stream_id}",
                flush=True,
            )
            return

        if path == "/app/3":
            if APP_PATHS != [
                "/app/1",
                "/app/2",
                "/app/3",
            ]:
                raise RuntimeError(
                    "APP_PATH_SEQUENCE_INVALID"
                )

            if len(
                set(
                    [
                        APP_PROTOCOL
                    ]
                )
            ) != 1:
                raise RuntimeError(
                    "APP_CONNECTION_INVALID"
                )

            print(
                "BROWSER_APP_PATHS_ONE_"
                "QUIC_CONNECTION=PASS",
                flush=True,
            )

            print(
                "FRESHNESS_ON_BROWSER_APP2=PASS",
                flush=True,
            )


async def main():
    configuration = \
        QuicConfiguration(
            is_client=False,
            alpn_protocols=H3_ALPN,
        )

    configuration.load_cert_chain(
        "/tls/server.pem",
        "/tls/server.key",
    )

    await serve(
        "0.0.0.0",
        4433,
        configuration=configuration,
        create_protocol=
            BrowserServerProtocol,
        retry=False,
    )

    print(
        "BROWSER_H3_SERVER_READY "
        "udp://0.0.0.0:4433",
        flush=True,
    )

    await asyncio.Future()


if __name__ == "__main__":
    asyncio.run(
        main()
    )

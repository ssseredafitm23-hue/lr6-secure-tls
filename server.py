import argparse
import socket
import ssl
import json
import secrets
import hmac
import re
import bcrypt

from common import (
    ROOT, CONFIG, TIMEOUT, MAX_PAYLOAD,
    ProtocolError, load_hmac_key,
    send_frame, recv_frame,
    sign, verify, log_event
)


def log(event, **fields):
    log_event("server", event, **fields)


def make_context(args):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)

    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.maximum_version = ssl.TLSVersion.TLSv1_3

    ctx.set_ciphers(
        "ECDHE+AESGCM:ECDHE+CHACHA20"
    )

    ctx.load_cert_chain(args.cert, args.key)
    ctx.options |= ssl.OP_NO_COMPRESSION

    if args.require_client_cert:
        ctx.load_verify_locations(cafile=args.ca)
        ctx.verify_mode = ssl.CERT_REQUIRED
        ctx.verify_flags |= ssl.VERIFY_X509_STRICT

    return ctx


def handle(tls, reader, users, dummy_hash, key, meta):

    def respond(obj, event, **fields):
        send_frame(tls, obj)
        log(event, **meta, **fields)

    request = recv_frame(reader)

    if request is None:
        return

    if request.get("op") != "auth":
        respond(
            {"ok": False, "err": "auth_required"},
            "auth.fail",
            reason="no_auth_message"
        )
        return

    username = request.get("username")
    password = request.get("password")

    valid_user = (
        isinstance(username, str)
        and re.fullmatch(
            r"[A-Za-z0-9_.-]{1,64}", username
        ) is not None
    )

    if not valid_user:
        username = "<invalid>"

    valid_password = False
    password_bytes = b""

    if isinstance(password, str):
        try:
            password_bytes = password.encode("utf-8")
            valid_password = (
                1 <= len(password_bytes) <= 72
            )
        except UnicodeError:
            pass

    stored_hash = users.get(username)

    target_hash = (
        stored_hash.encode("ascii")
        if stored_hash else dummy_hash
    )

    password_ok = bcrypt.checkpw(
        password_bytes if valid_password
        else b"invalid",
        target_hash
    )

    if not (
        valid_user
        and stored_hash
        and valid_password
        and password_ok
    ):
        respond(
            {"ok": False,
             "err": "invalid_credentials"},
            "auth.fail",
            user=username,
            reason="invalid_credentials"
        )
        return

    token = secrets.token_hex(32)
    expected_seq = 1

    respond(
        {"ok": True, "token": token},
        "auth.ok",
        user=username
    )

    while True:
        request = recv_frame(reader)

        if request is None:
            return

        op = request.get("op")

        if op == "quit":
            respond(
                {"ok": True, "bye": True},
                "session.end",
                user=username
            )
            return

        if op != "data":
            respond(
                {"ok": False,
                 "err": "unsupported_op"},
                "data.rejected",
                user=username,
                reason="unsupported_op"
            )
            continue

        supplied_token = request.get("token")

        token_ok = (
            isinstance(supplied_token, str)
            and re.fullmatch(
                r"[0-9a-f]{64}", supplied_token
            ) is not None
            and hmac.compare_digest(
                token, supplied_token
            )
        )

        if not token_ok:
            respond(
                {"ok": False,
                 "err": "invalid_token"},
                "data.invalid_token",
                user=username
            )
            continue

        if not verify(key, request):
            respond(
                {"ok": False, "err": "bad_hmac"},
                "data.bad_hmac",
                user=username
            )
            continue

        seq = request.get("seq")

        if type(seq) is not int or seq != expected_seq:
            respond(
                {"ok": False, "err": "invalid_sequence"},
                "data.replay_rejected",
                user=username
            )
            continue

        payload = request.get("payload")

        try:
            if not isinstance(payload, str):
                raise ValueError

            payload_size = len(payload.encode("utf-8"))

            if payload_size > MAX_PAYLOAD:
                raise ValueError

        except (ValueError, UnicodeError):
            respond(
                {"ok": False, "err": "invalid_payload"},
                "data.rejected",
                user=username,
                reason="invalid_payload"
            )
            continue

        response = {
            "op": "data_result",
            "ok": True,
            "seq": seq,
            "echo": payload
        }

        response["hmac"] = sign(key, response)

        respond(
            response,
            "data.ok",
            user=username,
            seq=seq,
            bytes=payload_size,
            code="OK"
        )

        expected_seq += 1


def serve_connection(raw, peer, ctx, users,
                     dummy_hash, key):

    meta = {
        "ip": peer[0],
        "port": peer[1],
        "connection_id": secrets.token_hex(8)
    }

    log("conn.accepted", **meta)
    raw.settimeout(TIMEOUT)

    try:
        with ctx.wrap_socket(
            raw,
            server_side=True,
            do_handshake_on_connect=False
        ) as tls:

            try:
                tls.do_handshake()

            except (ssl.SSLError, OSError) as exc:
                log(
                    "tls.handshake.fail",
                    **meta,
                    reason=getattr(exc, "reason", None)
                           or type(exc).__name__
                )
                return

            log(
                "tls.handshake.ok",
                **meta,
                tls_version=tls.version(),
                cipher=tls.cipher()[0],
                client_cert=bool(tls.getpeercert())
            )

            with tls.makefile("rb") as reader:
                try:
                    handle(
                        tls, reader, users,
                        dummy_hash, key, meta
                    )

                except ProtocolError:
                    log(
                        "protocol.error",
                        **meta,
                        reason="invalid_frame"
                    )

                    send_frame(
                        tls,
                        {"ok": False,
                         "err": "invalid_frame"}
                    )

    except (OSError, ssl.SSLError) as exc:
        log(
            "conn.error",
            **meta,
            reason=type(exc).__name__
        )

    finally:
        log("conn.closed", **meta)


def main():
    parser = argparse.ArgumentParser(
        description="Lab6 Secure TLS Server"
    )

    parser.add_argument(
        "--host", default="127.0.0.1"
    )
    parser.add_argument(
        "--port", type=int, default=8443
    )
    parser.add_argument(
        "--cert", default=str(ROOT / "certs/server.crt")
    )
    parser.add_argument(
        "--key", default=str(ROOT / "certs/server.key")
    )
    parser.add_argument(
        "--ca", default=str(ROOT / "certs/ca.crt")
    )
    parser.add_argument(
        "--require-client-cert", action="store_true"
    )

    args = parser.parse_args()

    users = json.loads(
        (CONFIG / "users.json").read_text()
    )

    key = load_hmac_key()

    dummy_hash = bcrypt.hashpw(
        secrets.token_bytes(32),
        bcrypt.gensalt(rounds=12)
    )

    ctx = make_context(args)

    with socket.socket(
        socket.AF_INET, socket.SOCK_STREAM
    ) as listener:

        listener.setsockopt(
            socket.SOL_SOCKET,
            socket.SO_REUSEADDR, 1
        )

        listener.bind((args.host, args.port))
        listener.listen(16)

        print("=== Lab6 Secure TLS Server ===")
        print(f"Listening on {args.host}:{args.port}")
        print("TLS versions: 1.2 / 1.3")
        print("mTLS:", args.require_client_cert)
        print("Press Ctrl+C to stop")

        log(
            "server.started",
            host=args.host,
            port=args.port,
            mtls=args.require_client_cert
        )

        try:
            while True:
                raw, peer = listener.accept()

                with raw:
                    serve_connection(
                        raw, peer, ctx, users,
                        dummy_hash, key
                    )

        except KeyboardInterrupt:
            print("\nServer stopped")

        finally:
            log("server.stopped")


if __name__ == "__main__":
    main()

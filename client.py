import argparse
import socket
import ssl
import getpass
import hashlib
import re

from common import (
    ROOT, TIMEOUT, MAX_PAYLOAD,
    ProtocolError, load_hmac_key,
    send_frame, recv_frame,
    sign, verify, log_event
)


def log(event, **fields):
    log_event("client", event, **fields)


def make_context(args):
    ctx = ssl.create_default_context(
        ssl.Purpose.SERVER_AUTH,
        cafile=args.ca
    )

    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.maximum_version = ssl.TLSVersion.TLSv1_3

    ctx.check_hostname = True
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.verify_flags |= ssl.VERIFY_X509_STRICT
    ctx.options |= ssl.OP_NO_COMPRESSION

    ctx.set_ciphers(
        "ECDHE+AESGCM:ECDHE+CHACHA20"
    )

    if args.tls == "1.2":
        ctx.maximum_version = ssl.TLSVersion.TLSv1_2

    elif args.tls == "1.3":
        ctx.minimum_version = ssl.TLSVersion.TLSv1_3

    if args.cert and args.key:
        ctx.load_cert_chain(args.cert, args.key)

    return ctx


def format_name(name):
    return ", ".join(
        f"{k}={v}"
        for group in name
        for k, v in group
    )


def show_tls_info(tls):
    cert = tls.getpeercert()
    fingerprint = hashlib.sha256(
        tls.getpeercert(binary_form=True)
    ).hexdigest()

    print("\n=== TLS Session ===")
    print("Protocol:", tls.version())
    print("Cipher:", tls.cipher()[0])
    print("Certificate verification: OK")
    print("Subject:", format_name(cert["subject"]))
    print("Issuer:", format_name(cert["issuer"]))
    print("Valid from:", cert["notBefore"])
    print("Valid until:", cert["notAfter"])
    print("SHA-256:", fingerprint)
    print("SAN:", cert.get("subjectAltName"))

    return fingerprint


def receive(reader):
    response = recv_frame(reader)

    if response is None:
        raise ProtocolError("Unexpected disconnect")

    return response


def run(args):
    stage = "configuration"

    try:
        ctx = make_context(args)
        key = load_hmac_key()

        password = getpass.getpass("Password: ")

        if not 1 <= len(password.encode("utf-8")) <= 72:
            print("ERROR: Invalid password length")
            log("input.rejected", reason="password_length")
            return 1

        if len(args.msg.encode("utf-8")) > MAX_PAYLOAD:
            print("ERROR: Message too large")
            log("input.rejected", reason="payload_length")
            return 1

        stage = "connection"

        log(
            "conn.attempt",
            host=args.host,
            port=args.port,
            server_name=args.server_name
        )

        with socket.create_connection(
            (args.host, args.port),
            timeout=TIMEOUT
        ) as raw:

            stage = "tls_handshake"

            with ctx.wrap_socket(
                raw,
                server_hostname=args.server_name
            ) as tls:

                fingerprint = show_tls_info(tls)

                log(
                    "tls.handshake.ok",
                    tls_version=tls.version(),
                    cipher=tls.cipher()[0],
                    certificate_sha256=fingerprint,
                    server_name=args.server_name
                )

                with tls.makefile("rb") as reader:

                    stage = "authentication"

                    send_frame(tls, {
                        "op": "auth",
                        "username": args.user,
                        "password": password
                    })

                    del password

                    response = receive(reader)

                    if response.get("ok") is not True:
                        print("\nAUTH FAILED")
                        log(
                            "auth.fail",
                            user=args.user,
                            reason="authentication_rejected"
                        )
                        return 1

                    token = response.get("token")

                    if not (
                        isinstance(token, str)
                        and re.fullmatch(
                            r"[0-9a-f]{64}", token
                        )
                    ):
                        raise ProtocolError(
                            "Invalid session token"
                        )

                    print("\nAUTH OK")
                    print("User:", args.user)
                    print("Session token received")

                    log("auth.ok", user=args.user)

                    stage = "data_exchange"

                    request = {
                        "op": "data",
                        "token": token,
                        "seq": 1,
                        "payload": args.msg
                    }

                    request["hmac"] = sign(
                        key, request
                    )

                    send_frame(tls, request)

                    print("\n=== Data Exchange ===")
                    print("Sent:", args.msg)

                    response = receive(reader)

                    if response.get("ok") is not True:
                        print("DATA REJECTED")
                        log("data.rejected")
                        return 1

                    if not verify(key, response):
                        print("ERROR: Response HMAC invalid")
                        log("data.bad_hmac")
                        return 1

                    if (
                        response.get("op") != "data_result"
                        or type(response.get("seq")) is not int
                        or response["seq"] != 1
                        or response.get("echo") != args.msg
                    ):
                        raise ProtocolError(
                            "Unexpected server response"
                        )

                    print("Received:", response["echo"])
                    print("Response HMAC: VALID")
                    print("Data integrity: VERIFIED")

                    log(
                        "data.ok",
                        user=args.user,
                        seq=1,
                        bytes=len(args.msg.encode("utf-8")),
                        integrity=True
                    )

                    stage = "session_end"

                    send_frame(tls, {"op": "quit"})
                    response = receive(reader)

                    if not (
                        response.get("ok") is True
                        and response.get("bye") is True
                    ):
                        raise ProtocolError(
                            "Invalid closing response"
                        )

                    print("\nSession closed successfully")
                    log("session.end", user=args.user)

                    return 0

    except ssl.SSLCertVerificationError as exc:
        print("TLS CERTIFICATE VERIFICATION FAILED")
        print("Verify code:", exc.verify_code)

        log(
            "tls.certificate.fail",
            stage=stage,
            verify_code=exc.verify_code
        )

    except ssl.SSLError as exc:
        reason = exc.reason or "SSL_ERROR"

        print("TLS ERROR:", reason)

        log(
            "tls.error",
            stage=stage,
            reason=reason
        )

    except ProtocolError:
        print("ERROR: Invalid protocol response")
        log("protocol.error", stage=stage)

    except (OSError, ValueError, UnicodeError) as exc:
        print("ERROR:", type(exc).__name__)

        log(
            "client.error",
            stage=stage,
            reason=type(exc).__name__
        )

    finally:
        log("conn.finished", stage=stage)

    return 1


def main():
    parser = argparse.ArgumentParser(
        description="Lab6 Secure TLS Client"
    )

    parser.add_argument(
        "--host", default="127.0.0.1"
    )
    parser.add_argument(
        "--port", type=int, default=8443
    )
    parser.add_argument(
        "--server-name", default="localhost"
    )
    parser.add_argument(
        "--ca", default=str(ROOT / "certs/ca.crt")
    )
    parser.add_argument("--cert")
    parser.add_argument("--key")
    parser.add_argument(
        "--user", default="alice"
    )
    parser.add_argument(
        "--msg", default="Hello Secure TLS"
    )
    parser.add_argument(
        "--tls",
        choices=["auto", "1.2", "1.3"],
        default="auto"
    )

    args = parser.parse_args()

    if bool(args.cert) != bool(args.key):
        parser.error("--cert and --key must be used together")

    raise SystemExit(run(args))


if __name__ == "__main__":
    main()

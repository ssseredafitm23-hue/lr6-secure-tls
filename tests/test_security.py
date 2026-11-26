import unittest
import socket
import ssl
import getpass
import bcrypt
import json

from contextlib import contextmanager

from common import (
    ROOT, CONFIG, TIMEOUT, MAX_PAYLOAD,
    load_hmac_key, send_frame,
    recv_frame, sign, verify
)


class SecurityTests(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.key = load_hmac_key()

        cls.password = getpass.getpass(
            "Test user alice password: "
        )

        users = json.loads(
            (CONFIG / "users.json").read_text()
        )

        if not bcrypt.checkpw(
            cls.password.encode("utf-8"),
            users["alice"].encode("ascii")
        ):
            raise RuntimeError(
                "Incorrect test password"
            )

    @contextmanager
    def connection(self, version=None):
        ctx = ssl.create_default_context(
            cafile=str(ROOT / "certs/ca.crt")
        )

        ctx.minimum_version = ssl.TLSVersion.TLSv1_2

        if version is not None:
            ctx.minimum_version = version
            ctx.maximum_version = version

        with socket.create_connection(
            ("127.0.0.1", 8443),
            timeout=TIMEOUT
        ) as raw:

            with ctx.wrap_socket(
                raw, server_hostname="localhost"
            ) as tls:

                with tls.makefile("rb") as reader:
                    yield tls, reader

    def exchange(self, tls, reader, message):
        send_frame(tls, message)
        response = recv_frame(reader)
        self.assertIsNotNone(response)
        return response

    def authenticate(self, tls, reader):
        response = self.exchange(
            tls, reader,
            {
                "op": "auth",
                "username": "alice",
                "password": self.password
            }
        )

        self.assertIs(response["ok"], True)
        return response["token"]

    def data_message(self, token, seq=1,
                     payload="Lab6 test"):
        message = {
            "op": "data",
            "token": token,
            "seq": seq,
            "payload": payload
        }

        message["hmac"] = sign(self.key, message)
        return message

    def assert_rejected(self, response, reason):
        self.assertIs(response["ok"], False)
        self.assertEqual(response["err"], reason)

    def test_tls12_roundtrip(self):
        with self.connection(
            ssl.TLSVersion.TLSv1_2
        ) as (tls, reader):

            self.assertEqual(tls.version(), "TLSv1.2")

            token = self.authenticate(tls, reader)

            response = self.exchange(
                tls, reader,
                self.data_message(token)
            )

            self.assertIs(response["ok"], True)
            self.assertEqual(response["echo"], "Lab6 test")
            self.assertTrue(verify(self.key, response))

    def test_tls13_roundtrip(self):
        with self.connection(
            ssl.TLSVersion.TLSv1_3
        ) as (tls, reader):

            self.assertEqual(tls.version(), "TLSv1.3")

            token = self.authenticate(tls, reader)

            response = self.exchange(
                tls, reader,
                self.data_message(token)
            )

            self.assertIs(response["ok"], True)
            self.assertEqual(response["echo"], "Lab6 test")
            self.assertTrue(verify(self.key, response))

    def test_auth_required(self):
        with self.connection() as (tls, reader):
            response = self.exchange(
                tls, reader, {"op": "data"}
            )

            self.assert_rejected(
                response, "auth_required"
            )

    def test_unknown_user(self):
        with self.connection() as (tls, reader):
            response = self.exchange(
                tls, reader,
                {
                    "op": "auth",
                    "username": "unknown_user",
                    "password": "Invalid-Test-Password"
                }
            )

            self.assert_rejected(
                response, "invalid_credentials"
            )

    def test_invalid_token(self):
        with self.connection() as (tls, reader):
            self.authenticate(tls, reader)

            response = self.exchange(
                tls, reader,
                self.data_message("0" * 64)
            )

            self.assert_rejected(
                response, "invalid_token"
            )

    def test_modified_payload(self):
        with self.connection() as (tls, reader):
            token = self.authenticate(tls, reader)
            message = self.data_message(token)

            message["payload"] = "Modified data"

            response = self.exchange(
                tls, reader, message
            )

            self.assert_rejected(
                response, "bad_hmac"
            )

    def test_repeated_sequence(self):
        with self.connection() as (tls, reader):
            token = self.authenticate(tls, reader)
            message = self.data_message(token)

            first = self.exchange(
                tls, reader, message
            )

            self.assertIs(first["ok"], True)

            second = self.exchange(
                tls, reader, message
            )

            self.assert_rejected(
                second, "invalid_sequence"
            )

    def test_expired_session_token(self):
        with self.connection() as (tls, reader):
            old_token = self.authenticate(tls, reader)

            response = self.exchange(
                tls, reader, {"op": "quit"}
            )

            self.assertIs(response["bye"], True)

        with self.connection() as (tls, reader):
            new_token = self.authenticate(tls, reader)

            self.assertNotEqual(old_token, new_token)

            response = self.exchange(
                tls, reader,
                self.data_message(old_token)
            )

            self.assert_rejected(
                response, "invalid_token"
            )

    def test_invalid_json(self):
        with self.connection() as (tls, reader):
            tls.sendall(b'{"invalid":\n')

            response = recv_frame(reader)

            self.assert_rejected(
                response, "invalid_frame"
            )

    def test_oversized_payload(self):
        with self.connection() as (tls, reader):
            token = self.authenticate(tls, reader)

            response = self.exchange(
                tls, reader,
                self.data_message(
                    token,
                    payload="A" * (MAX_PAYLOAD + 1)
                )
            )

            self.assert_rejected(
                response, "invalid_payload"
            )

    def test_response_integrity(self):
        with self.connection() as (tls, reader):
            token = self.authenticate(tls, reader)

            response = self.exchange(
                tls, reader,
                self.data_message(token)
            )

            self.assertTrue(
                verify(self.key, response)
            )

            response["echo"] = "Modified response"

            self.assertFalse(
                verify(self.key, response)
            )

    def test_untrusted_certificate(self):
        ctx = ssl.SSLContext(
            ssl.PROTOCOL_TLS_CLIENT
        )

        ctx.minimum_version = ssl.TLSVersion.TLSv1_2

        with socket.create_connection(
            ("127.0.0.1", 8443),
            timeout=TIMEOUT
        ) as raw:

            with self.assertRaises(
                ssl.SSLCertVerificationError
            ):
                with ctx.wrap_socket(
                    raw,
                    server_hostname="localhost"
                ):
                    pass


if __name__ == "__main__":
    unittest.main(verbosity=2)

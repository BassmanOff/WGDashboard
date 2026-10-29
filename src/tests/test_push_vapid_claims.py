"""
Регрессионные тесты VAPID claims push-уведомлений (RFC 8292).

Проверяется, что aud в авторизационном JWT — это origin push-сервиса,
выведенный из endpoint'а подписки, а НЕ origin веб-панели. По RFC 8292
§4.1 push-сервис сверяет aud со своим origin; раньше код передавал
aud = origin панели, из-за чего FCM/autopush отвечали 401
"audience mismatch".

Сквозной тест выполняется через реальный DashboardPushNotifications
(временная SQLite-БД) и настоящий pywebpush против локальной заглушки
push-сервиса, поэтому он также ловит:
- регресс aud (кто-то снова подставит origin панели в claims);
- регресс формата ключа (PEM-строка вместо экземпляра Vapid01).
"""
import base64
import json
import os
import sys
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from unittest.mock import patch

# Позволяет запускать тесты из src/ (импортируем пакет modules)
SRC = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SRC))

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

import modules.DashboardPushNotifications as pushModule
from modules.DashboardPushNotifications import DashboardPushNotifications

PANEL_ORIGIN = "http://80.66.72.157:10086"  # типичный «плохой» aud — origin панели


class _StubConfig:
    """Минимальный стаб DashboardConfig.GetConfig."""

    def __init__(self, sendFrom: str = "ops@example.com"):
        self.sendFrom = sendFrom

    def GetConfig(self, section: str, key: str) -> tuple[bool, str]:
        assert (section, key) == ("Email", "send_from")
        return True, self.sendFrom


class _StubLogger:
    """Заменяет DashboardLogger, чтобы тест не трогал log-БД панели."""

    def log(self, *args, **kwargs):
        pass


class _CaptureHandler(BaseHTTPRequestHandler):
    """Заглушка push-сервиса: фиксирует Authorization, отвечает 201."""

    def do_POST(self):  # noqa: N802 (BaseHTTPRequestHandler API)
        length = int(self.headers.get("Content-Length", 0))
        self.rfile.read(length)
        self.server.authorization = self.headers.get("Authorization")
        self.send_response(201)
        self.end_headers()

    def log_message(self, *args):  # глушим лог тестового сервера
        pass


def makeInstance(sendFrom: str = "ops@example.com"):
    """Экземпляр модуля на временной SQLite-БД (не трогает БД панели)."""
    tmp = tempfile.TemporaryDirectory()
    dbPath = os.path.join(tmp.name, "wgdashboard_push_test.db")
    with patch.object(pushModule, "ConnectionString",
                      lambda database: f"sqlite:///{dbPath}"), \
         patch.object(pushModule, "DashboardLogger",
                      lambda: _StubLogger()):
        # peerPayments не используется в тестируемом пути
        inst = DashboardPushNotifications(_StubConfig(sendFrom), None)
    return inst, tmp


def buildClaims(sendFrom: str = "ops@example.com") -> dict:
    """Claims приватного метода __getVapidClaims (точечные проверки)."""
    inst, tmp = makeInstance(sendFrom)
    try:
        return inst._DashboardPushNotifications__getVapidClaims()  # noqa: SLF001
    finally:
        inst.engine.dispose()  # Windows: иначе файл БД занят
        tmp.cleanup()


def generateSubscriptionKeys() -> tuple[str, str]:
    """p256dh/auth — валидная пара: pywebpush делает ECDH с публичным
    ключом подписки до отправки, случайные байты не годятся."""
    subPriv = ec.generate_private_key(ec.SECP256R1())
    rawPoint = subPriv.public_key().public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.UncompressedPoint,
    )
    p256dh = base64.urlsafe_b64encode(rawPoint).decode().rstrip("=")
    auth = base64.urlsafe_b64encode(os.urandom(16)).decode().rstrip("=")
    return p256dh, auth


def b64pad(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


class VapidClaimsTests(unittest.TestCase):
    def test_claims_contain_sub_and_no_aud(self):
        """__getVapidClaims задаёт только sub; aud оставляем pywebpush."""
        claims = buildClaims("ops@example.com")
        self.assertEqual(set(claims.keys()), {"sub"})
        self.assertEqual(claims["sub"], "mailto:ops@example.com")

    def test_claims_default_sub_without_send_from(self):
        """Пустой send_from даёт дефолтный mailto-контакт."""
        claims = buildClaims("")
        self.assertEqual(claims["sub"], "mailto:admin@localhost")
        self.assertNotIn("aud", claims)

    def test_sendone_jwt_aud_is_push_service_origin(self):
        """Сквозной тест: __sendOne + настоящий pywebpush -> JWT.

        aud в JWT должен совпасть с origin endpoint'а подписки. Если aud
        задан вручную (например, origin панели), pywebpush подставит его
        «как есть» и тест упадёт. Также здесь ловятся: передача ключа в
        неприемлемом формате (PEM-строка вместо Vapid01) и рассинхрон
        подписи JWT с публичным ключом k=.
        """
        from pywebpush import webpush

        # auth возвращается объектом-заглушкой push-сервиса
        server = HTTPServer(("127.0.0.1", 0), _CaptureHandler)
        server.authorization = None
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        inst, tmp = makeInstance("ops@example.com")
        try:
            port = server.server_address[1]
            endpointOrigin = f"http://127.0.0.1:{port}"
            endpoint = f"{endpointOrigin}/fcm/send/fake-token-123"
            p256dh, auth = generateSubscriptionKeys()

            ok, reason = inst._DashboardPushNotifications__sendOne(  # noqa: SLF001
                webpush,
                {"Endpoint": endpoint, "P256DH": p256dh, "Auth": auth},
                "ping")
            self.assertTrue(ok, f"__sendOne вернул ошибку: {reason}")

            authHeader = server.authorization
            self.assertIsNotNone(authHeader,
                                 "push-сервис не получил Authorization")
            token = authHeader.split("t=", 1)[1].split(",", 1)[0]
            headerB64, payloadB64, sigB64 = token.split(".")
            claims = json.loads(b64pad(payloadB64))

            # ключевые проверки регресса
            self.assertEqual(claims.get("aud"), endpointOrigin,
                             "aud должен быть origin push-сервиса из endpoint, "
                             f"а не адрес панели ({PANEL_ORIGIN})")
            self.assertNotEqual(claims.get("aud"), PANEL_ORIGIN)
            self.assertEqual(claims.get("sub"), "mailto:ops@example.com")

            # подпись JWT сверяем с публичным ключом k= (ECDSA P-256 SHA-256)
            keyB64 = authHeader.split("k=", 1)[1]
            publicKey = ec.EllipticCurvePublicKey.from_encoded_point(
                ec.SECP256R1(), b64pad(keyB64))
            rawSig = b64pad(sigB64)
            r, s = int.from_bytes(rawSig[:32], "big"), int.from_bytes(rawSig[32:], "big")
            publicKey.verify(
                encode_dss_signature(r, s),
                f"{headerB64}.{payloadB64}".encode("ascii"),
                ec.ECDSA(hashes.SHA256()))
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)
            inst.engine.dispose()  # Windows: иначе файл БД занят
            tmp.cleanup()


if __name__ == "__main__":
    unittest.main(verbosity=2)

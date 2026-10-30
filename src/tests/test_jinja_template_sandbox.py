"""
Регрессионные тесты безопасного рендеринга Jinja2-шаблонов.

Проверяется:
1. RenderSandboxedTemplate (маркер: helpers в modules/Utilities.py, API
   совпадает с оригинальным WGDashboard) - штатные шаблоны рендерятся,
   сандбокс запрещает опасные атрибуты (__class->__mro__ и т.п.);
2. RenderSandboxedTemplateSafe - на ошибки шаблона отдаётся только
   обобщённое сообщение: без traceback, путей, исходников шаблона;
3. Сузуние контекста: шаблон НЕ получает секретные поля (PrivateKey
   конфигурации) и внутренние объекты приложения;
4. Интеграция: Peer.downloadPeer() продолжает собирать рабочие .conf,
   включая случай, когда поле случайно выглядит как шаблон;
   WireguardConfiguration.updateConfigurationInfo() (OverridePeerSettings)
   отклоняет битый шаблон с безопасным сообщением.

Запуск из src/:  python -m unittest discover -s tests -v
"""
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace

SRC = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SRC))

import jinja2
from jinja2.exceptions import SecurityError, UndefinedError

from modules.Utilities import (
    RenderSandboxedTemplate, RenderSandboxedTemplateSafe)
from modules.Peer import Peer as PeerModel
from modules.WireguardConfiguration import WireguardConfiguration

SERVER_PRIVATE_KEY = "SERVERPRIVATEKEY8888"
PEER_PRIVATE_KEY = "PEERPRIVATEKEY123"


class HelperRenderTests(unittest.TestCase):
    """Штатные шаблоны + запреты сандбокса."""

    def test_plain_render_with_dict_context(self):
        self.assertEqual(
            RenderSandboxedTemplate("Hi {{ peer.name }}", peer={"name": "Alex"}),
            "Hi Alex")

    def test_render_shipped_email_like_body(self):
        template = (
            "Hi {{peer.name}},\n"
            "Your configuration {{configurationFile.fileName}}\n"
            "Use {{peer.preshared_key}} if asked."
        )
        context = dict(peer={"name": "Alex", "preshared_key": "PSK"},
                       configurationFile={"fileName": "a.conf"})
        self.assertEqual(
            RenderSandboxedTemplate(template, **context),
            "Hi Alex,\nYour configuration a.conf\nUse PSK if asked.")

    def test_undefined_variables_render_empty(self):
        """Документируем дефолтное поведение Jinja2: отсутствующая переменная
        рендерится пустой строкой (в шаблонах-заготовках это штатная ситуация)."""
        self.assertEqual(
            RenderSandboxedTemplate("[{{ unknown }}]"),
            "[]")

    def test_undefined_variables_in_loops_empty(self):
        """Дефолтное поведение: итерация по несуществующей переменной даёт
        пустой цикл без ошибки."""
        self.assertEqual(
            RenderSandboxedTemplate("{% for x in nope %}y{% endfor %}"),
            "")

    def test_sandbox_blocks_escape_paths(self):
        # jinja2 3.1.x: доступ к подчёркнутым атрибутам возвращает
        # "unsafe undefined", который поднимает SecurityError при
        # любом ИСПОЛЬЗОВАНИИ значения (цепочка/вызов) - значит наружу
        # ничего не утекает.
        for unsafe in (
                "{{ ''.__class__.__mro__ }}",
                "{{ ''.__class__.__mro__[1].__subclasses__() }}",
                "{{ ''.__init__.__globals__ }}",
        ):
            with self.assertRaises(SecurityError,
                                   msg=f"не должно экранироваться: {unsafe}"):
                RenderSandboxedTemplate(unsafe)

    def test_dict_context_underscore_access_is_undefined(self):
        """На подчёркнутом атрибуте без использования значение остаётся
        undefined и рендерится пустой строкой (документируем поведение
        jinja2 3.1.6)."""
        self.assertEqual(
            RenderSandboxedTemplate("[{{ peer.__class__ }}]", peer=dict(name="x")),
            "[]")


class SafeVariantTests(unittest.TestCase):
    """Ошибки шаблона наружу не тянут traceback/пути/исходники."""

    # Слова, подсказывающие, что наружу утёк traceback или реализация
    FORBIDDEN_MESSAGE_FRAGMENTS = (
        "Traceback", "File \"", ".py\"", "line, in ",
        SERVER_PRIVATE_KEY, PEER_PRIVATE_KEY,
    )

    def assertSafeMessage(self, message: str):
        for fragment in self.FORBIDDEN_MESSAGE_FRAGMENTS:
            self.assertNotIn(fragment, message)

    def test_valid_template(self):
        ok, result = RenderSandboxedTemplateSafe(
            "{{ peer.name }}/{{ suite }}", peer={"name": "Alex"}, suite="jinja")
        self.assertTrue(ok)
        self.assertEqual(result, "Alex/jinja")

    def test_broken_syntax_message_safe(self):
        source = "SECRETTOKENBODY {% if %}broken"
        ok, message = RenderSandboxedTemplateSafe(source)
        self.assertFalse(ok)
        self.assertIn("Invalid template syntax", message)
        self.assertSafeMessage(message)
        self.assertNotIn("SECRETTOKENBODY", message)
        self.assertNotIn("broken", message)

    def test_forbidden_operation_message_safe(self):
        for unsafe in (
                "{{ ''.__class__.__mro__ }}",
                "{{ ''.__class__.__mro__[1].__subclasses__ }}",
        ):
            ok, message = RenderSandboxedTemplateSafe(unsafe)
            self.assertFalse(ok, f"должен быть заблокирован: {unsafe}")
            self.assertIn("forbidden operations", message)
            self.assertSafeMessage(message)

    def test_unexpected_exception_message_generic(self):
        ok, message = RenderSandboxedTemplateSafe("{{ 1/0 }}")
        self.assertFalse(ok)
        self.assertEqual(message, "Template rendering failed")

    def test_iterating_undefined_is_handled_safely(self):
        ok, message = RenderSandboxedTemplateSafe("{% for %}")
        self.assertFalse(ok)
        self.assertSafeMessage(message)


def makePeerStub(endpointAllowedIPs: str):
    """Peer через __new__ (БД/ini не затрагиваются): атрибуты согласованы
    со скачанным .conf-файлом; configuration - узкий стаб с секретом."""
    peer = PeerModel.__new__(PeerModel)
    peer.id = "pubkey-test"
    peer.private_key = PEER_PRIVATE_KEY
    peer.DNS = ""
    peer.endpoint_allowed_ip = endpointAllowedIPs
    peer.name = "testpeer"
    peer.allowed_ip = "10.6.6.2/32"
    peer.mtu = 0
    peer.keepalive = 0
    peer.preshared_key = ""

    overrideSettings = SimpleNamespace(
        MTU=None, DNS=None, EndpointAllowedIPs=None,
        PeerRemoteEndpoint=None, ListenPort=None, PersistentKeepalive=None)
    peer.configuration = SimpleNamespace(
        Protocol="wg",
        Name="AWG",
        Status=False,
        # Секрет конфигурации: шаблон НЕ должен получать к нему доступ
        PrivateKey=SERVER_PRIVATE_KEY,
        PublicKey="server-pubkey",
        Address="10.6.6.0/24",
        ListenPort=443,
        configurationInfo=SimpleNamespace(OverridePeerSettings=overrideSettings),
        DashboardConfig=SimpleNamespace(
            GetConfig=lambda section, key: ("", "1.2.3.4")),
    )
    return peer

def makeConfigurationInfoStub():
    configurationInfo = SimpleNamespace(
        OverridePeerSettings=SimpleNamespace(model_validate=lambda value: value),
        model_dump=lambda: {},
        model_validate=lambda value: value)
    return configurationInfo

def makeWgConfigurationStub(**attributes):
    configuration = WireguardConfiguration.__new__(WireguardConfiguration)
    configuration.Name = "AWG"
    configuration.Protocol = "awg"
    configuration.Status = False
    configuration.PublicKey = "server-pubkey"
    # Секрет: не должен попадать в контекст рендеринга
    configuration.PrivateKey = SERVER_PRIVATE_KEY
    configuration.Address = "10.6.6.0/24"
    configuration.ListenPort = "443"
    configuration.configurationInfo = makeConfigurationInfoStub()
    configuration.storeConfigurationInfo = lambda: True
    for key, value in attributes.items():
        setattr(configuration, key, value)
    return configuration


class PeerDownloadRenderTests(unittest.TestCase):
    """Peer.downloadPeer(): юзабельные .conf + отсутствие утечек."""

    def test_normal_peer_file_rendered(self):
        peer = makePeerStub("0.0.0.0/0")
        result = peer.downloadPeer()
        self.assertIn("[Interface]", result["file"])
        # Продуктовая фича: файл пиера содержит собственный приватный ключ
        self.assertIn(f"PrivateKey = {PEER_PRIVATE_KEY}", result["file"])
        self.assertNotIn("{{", result["file"])

    def test_server_private_key_not_exposed_via_template(self):
        peer = makePeerStub("0.0.0.0/0 {{ configuration.PrivateKey }}")
        result = peer.downloadPeer()
        self.assertNotIn(SERVER_PRIVATE_KEY, result["file"])
        self.assertNotIn("{{ configuration.PrivateKey }}", result["file"])

    def test_allowed_existing_placeholders_still_render(self):
        peer = makePeerStub(
            "0.0.0.0/0, {{ configuration.Name }} {{ configuration.ListenPort }}")
        result = peer.downloadPeer()
        self.assertIn("AWG 443", result["file"])

    def test_broken_field_template_falls_back_to_built_file(self):
        peer = makePeerStub("{% if %}")
        result = peer.downloadPeer()  # не должно падать
        self.assertIn("{% if %}", result["file"])


class UpdateConfigurationInfoRenderTests(unittest.TestCase):
    """updateConfigurationInfo(OverridePeerSettings): безопасные ошибки
    и узкий контекст рендеринга."""

    def test_placeholder_renders_to_valid_value(self):
        configuration = makeWgConfigurationStub()
        status, msg, key = configuration.updateConfigurationInfo(
            "OverridePeerSettings", {"ListenPort": "{{ configuration.ListenPort }}"})
        self.assertEqual((status, msg, key), (True, None, None))

    def test_broken_template_rejected_with_safe_message(self):
        configuration = makeWgConfigurationStub()
        status, msg, key = configuration.updateConfigurationInfo(
            "OverridePeerSettings", {"DNS": "{% if %}"})
        self.assertFalse(status)
        self.assertIn("Invalid template syntax", msg)
        for fragment in ("Traceback", "File \"", ".py\""):
            self.assertNotIn(fragment, msg)

    def test_private_key_not_in_render_context(self):
        configuration = makeWgConfigurationStub()
        status, msg, key = configuration.updateConfigurationInfo(
            "OverridePeerSettings",
            {"DNS": "999.999.999.999 {{ configuration.PrivateKey }}"})
        # Секрет не в контексте -> рендерится "999.999.999.999" -> DNS
        # не валиден; сообщение валидатора содержит только отрендеренный
        # адрес, без секрета, traceback и исходника шаблона
        self.assertFalse(status)
        self.assertIn("999.999.999.999", msg or "")
        self.assertNotIn(SERVER_PRIVATE_KEY, msg or "")
        self.assertNotIn("Traceback", msg or "")
        self.assertNotIn("{{", msg or "")


if __name__ == "__main__":
    unittest.main(verbosity=2)

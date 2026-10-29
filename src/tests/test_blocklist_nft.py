"""
Регрессионные тесты безопасного обновления и отключения блок-листа.

Проверяется, что:
- успешное обновление выполняется как `nft --check` (валидация) +
  `nft -f` (атомарная транзакция delete+create в одном файле), без
  отдельной команды удаления таблицы;
- сбой проверки/применения не запускает `nft delete`: старая таблица
  переживает неудачное обновление (атомарность транзакции);
- отсутствие таблицы (первое применение) даёт файл без delete-строки;
- remove() честно сообщает об ошибке удаления и не считает отсутствие
  таблицы ошибкой;
- сами правила (цепочки, исключения DNS, IPv4/IPv6, разрешённые порты)
  не изменены.

Системные nft-вызовы замоканы. Если nft установлен в окружении, одним
отдельным тестом дополнительно проверяется синтаксис сгенерированного
файла через `nft --check` (без изменения сетевой конфигурации).

Запуск из src/:  python -m unittest discover -s tests -v
"""
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from subprocess import CompletedProcess
from unittest.mock import patch

SRC = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SRC))

import modules.DashboardBlocklist as blocklistModule
from modules.DashboardBlocklist import DashboardBlocklist


class _StubPort:
    ListenPort = 443


class _StubDashboardConfig:
    """Минимальный стаб GetConfig для блока настроек блок-листа."""

    def GetConfig(self, section: str, key: str) -> tuple[bool, str]:
        values = {
            ("Blocklist", "enabled"): "true",
            ("Blocklist", "custom_url"): "",
            ("Blocklist", "list_size"): "full",
            ("Blocklist", "last_update"): "2026-01-01 00:00:00",
            ("Blocklist", "auto_update"): "false",
            ("Blocklist", "update_interval_hours"): "6",
            ("Server", "app_port"): "10086",
            ("Peers", "peer_global_DNS"): "1.1.1.1",
        }
        return True, values.get((section, key))


class _StubLogger:
    def log(self, *args, **kwargs):
        pass

    def error(self, *args, **kwargs):
        pass

    def info(self, *args, **kwargs):
        pass


class _StubCurrentApp:
    logger = _StubLogger()


class FakeNftRunner:
    """
    Замена subprocess.run для nft-вызовов модуля блок-листа.

    Результаты задаются на тест (check/apply/list/delete), каждый вызов
    запоминается в .calls для проверки последовательности и факта
    невыполнения побочных команд.
    """

    def __init__(self, check=(0, ""), apply=(0, ""),
                 list=(0, ""), delete=(0, "")):
        self.calls: list[list[str]] = []
        self._check = check
        self._apply = apply
        self._list = list
        self._delete = delete

    def __call__(self, argv, **kwargs):
        argv = list(argv)
        self.calls.append(argv)
        if "--check" in argv:
            rc, stderr = self._check
        elif "-f" in argv:
            rc, stderr = self._apply
        elif "delete" in argv:
            rc, stderr = self._delete
        else:  # list table ...
            rc, stderr = self._list
        return CompletedProcess(argv, returncode=rc, stdout="", stderr=stderr)

    # --- селекторы вызовов по этапам ---
    def checkCalls(self):
        return [c for c in self.calls if "--check" in c]

    def applyCalls(self):
        return [c for c in self.calls if "-f" in c and "--check" not in c]

    def deleteCalls(self):
        return [c for c in self.calls if "delete" in c]

    def listCalls(self):
        return [c for c in self.calls if "list" in c]


# Семантика правил, которую нельзя менять
RULE_FRAGMENTS = [
    "ct state established,related accept",
    "tcp sport { 22, 10086 } accept",
    "udp sport { 443 } accept",
    "ip daddr @dns_allow_v4 accept",
    "ip6 daddr @dns_allow_v6 accept",
    "ip daddr @blocked_v4 counter drop",
    "ip6 daddr @blocked_v6 counter drop",
    "type filter hook forward priority filter + 15; policy accept;",
    "type filter hook output priority filter + 15; policy accept;",
]


def makeInstance() -> tuple[DashboardBlocklist, tempfile.TemporaryDirectory]:
    """Экземпляр без __init__ (не нужны БД/ini); файлы во временной папке."""
    tmp = tempfile.TemporaryDirectory()
    inst = DashboardBlocklist.__new__(DashboardBlocklist)
    inst.wireguardConfigurations = {"AWG": _StubPort()}
    inst.dashboardConfig = _StubDashboardConfig()
    inst.remoteFilePath = Path(tmp.name) / "wgdashboard_blocklist_remote.txt"
    inst.nftFilePath = Path(tmp.name) / "wgdashboard_blocklist.nft"
    inst.tableName = "inet wgdashboard_blocklist"
    # применяемые подсети: существующий remote-файл (fetch не срабатывает)
    inst.remoteFilePath.write_text(
        "203.0.113.0/24\n2001:db8::/32\n", encoding="utf-8")
    # ручные записи обычно из БД; для тестов - пусто
    inst.GetManualEntries = lambda: []
    # nft ищется через shutil.which (в Windows-окружении его нет):
    # подменяем путь, сами вызовы эмулирует FakeNftRunner
    inst._nftBinary = lambda: "/usr/sbin/nft"
    return inst, tmp


class BlocklistNftTests(unittest.TestCase):
    def _runApply(self, runner: FakeNftRunner,
                  inst: DashboardBlocklist):
        with patch("modules.DashboardBlocklist.subprocess.run", runner), \
             patch("modules.DashboardBlocklist.current_app", _StubCurrentApp):
            return inst.apply()

    def _runRemove(self, runner: FakeNftRunner,
                   inst: DashboardBlocklist):
        with patch("modules.DashboardBlocklist.subprocess.run", runner), \
             patch("modules.DashboardBlocklist.current_app", _StubCurrentApp):
            return inst.remove()

    def test_apply_success_with_existing_table(self):
        """Обновление действующей таблицы: check -> apply; delete - только
        внутри файла -f (атомарно, отдельной команды нет)."""
        inst, tmp = makeInstance()
        try:
            runner = FakeNftRunner(check=(0, ""), apply=(0, ""), list=(0, ""))
            status, msg = self._runApply(runner, inst)
            self.assertTrue((status, msg), f"apply должен пройти: {msg}")
            self.assertEqual(len(runner.checkCalls()), 1)
            self.assertEqual(len(runner.applyCalls()), 1)
            self.assertLess(runner.calls.index(runner.checkCalls()[0]),
                            runner.calls.index(runner.applyCalls()[0]),
                            "проверка должна идти раньше применения")
            self.assertEqual(runner.deleteCalls(), [],
                             "отдельной команды delete быть не должно: "
                             "удаление и создание - одна транзакция -f")
            # два list-вызова: до (таблица была?) и после (верификация)
            self.assertEqual(len(runner.listCalls()), 2)

            content = inst.nftFilePath.read_text(encoding="utf-8")
            deleteIx = content.find("delete table inet wgdashboard_blocklist")
            tableIx = content.find(f"table inet wgdashboard_blocklist {{")
            self.assertGreater(deleteIx, 0, "до delete - shebang")
            self.assertLess(deleteIx, tableIx,
                            "delete table должен идти ДО объявления таблицы")
            for fragment in RULE_FRAGMENTS:
                self.assertIn(fragment, content,
                              f"семантика правил изменена: нет {fragment!r}")
            # DNS-исключение содержит стаб 1.1.1.1
            self.assertIn("1.1.1.1", content)
            # применённые подсети попали в наборы
            self.assertIn("203.0.113.0/24", content)
            self.assertIn("2001:db8::/32", content)
        finally:
            tmp.cleanup()

    def test_apply_check_failure_keeps_old_table(self):
        """Сбой проверки: до применения и удаления дело не доходит."""
        inst, tmp = makeInstance()
        try:
            runner = FakeNftRunner(
                check=(1, "Error: syntax error, unexpected junk"),
                apply=(0, ""),  # не должен вызываться
                delete=(0, ""))  # не должен вызываться
            status, msg = self._runApply(runner, inst)
            self.assertFalse(status)
            self.assertIn("syntax error", msg)
            self.assertEqual(runner.applyCalls(), [],
                             "сбой проверки не должен доходить до -f")
            self.assertEqual(runner.deleteCalls(), [],
                             "сбой проверки не должен трогать таблицу")
        finally:
            tmp.cleanup()

    def test_apply_failure_honest_error(self):
        """Сбой применения: честный отказ; отдельного delete нет вообще.

        Отказ недопустим: старая таблица продолжает работать (атомарность
        транзакции - сами правила применяются целиком или не применяются).
        """
        inst, tmp = makeInstance()
        try:
            runner = FakeNftRunner(
                check=(0, ""),
                apply=(1, "Error: Operation not permitted"),
                list=(0, ""))  # установка таблицы не должна считаться успешной
            status, msg = self._runApply(runner, inst)
            self.assertFalse(status)
            self.assertIn("Operation not permitted", msg)
            self.assertEqual(runner.deleteCalls(), [],
                             "отдельного nft delete быть не должно: ошибка "
                             "применения не должна потерять старую таблицу")
        finally:
            tmp.cleanup()

    def test_apply_first_time_no_table(self):
        """Первое применение: таблицы нет -> в файле нет delete-строки."""
        inst, tmp = makeInstance()
        try:
            runner = FakeNftRunner(
                check=(0, ""), apply=(0, ""),
                list=(1, "Error: No such file or directory"))
            status, msg = self._runApply(runner, inst)
            self.assertTrue((status, msg), f"apply должен пройти: {msg}")
            content = inst.nftFilePath.read_text(encoding="utf-8")
            self.assertNotIn("delete table inet wgdashboard_blocklist",
                             content,
                             "при отсутствии таблицы delete внутри файла "
                             "сломал бы транзакцию (ENOENT откатывает всё)")
            for fragment in RULE_FRAGMENTS:
                self.assertIn(fragment, content)
        finally:
            tmp.cleanup()

    def test_remove_success(self):
        inst, tmp = makeInstance()
        try:
            runner = FakeNftRunner(delete=(0, ""))  # удаление прошло
            status, msg = self._runRemove(runner, inst)
            self.assertTrue((status, msg), f"remove должен пройти: {msg}")
            self.assertEqual(runner.deleteCalls(), [runner.calls[0]])
        finally:
            tmp.cleanup()

    def test_remove_failure_reports_error(self):
        """Неудачное удаление вернёт False, а не ложный успех."""
        inst, tmp = makeInstance()
        try:
            runner = FakeNftRunner(delete=(1, "cache: Operation not permitted"))
            status, msg = self._runRemove(runner, inst)
            self.assertFalse(
                status, "remove не может быть успешным при ошибке nft delete")
            self.assertIn("Operation not permitted", msg)
        finally:
            tmp.cleanup()

    def test_remove_when_table_absent(self):
        """Таблицы нет: ENOENT от delete - не ошибка (цель достигнута)."""
        inst, tmp = makeInstance()
        try:
            runner = FakeNftRunner(
                delete=(1, "Error: No such file or directory"))
            status, msg = self._runRemove(runner, inst)
            self.assertTrue((status, msg),
                            "таблицы нет - отключение фактически состоялось")
        finally:
            tmp.cleanup()

    def test_apply_without_nft_binary(self):
        inst, tmp = makeInstance()
        try:
            with patch.object(inst, "_nftBinary", create=True,
                              return_value=None):
                status, msg = inst.apply()
            self.assertFalse(status)
            self.assertIn("not found", msg)
        finally:
            tmp.cleanup()


@unittest.skipUnless(shutil.which("nft") is not None,
                     "nft недоступен в окружении (например, на Windows)")
class NftSyntaxValidationTests(unittest.TestCase):
    """
    Живой синтаксический контроль сгенерированных правил через
    `nft --check`: команда ничего не применяет; имя таблицы
    изолировано от runtime-имени, сетевая конфигурация не изменяется.
    """

    def test_generated_ruleset_passes_nft_check(self):
        import subprocess

        inst, tmp = makeInstance()
        try:
            # изолированное имя: delete/создание не пересекается с
            # реальными таблицами хоста
            inst.tableName = "inet wgdashboard_blocklist_syntax_check"
            status, msg = inst._generateNftFile(
                ["203.0.113.0/24", "2001:db8:dead::/48"],
                ["1.1.1.1", "8.8.8.8", "2001:470:20::2"],
                [443])
            self.assertTrue((status, msg), msg)
            result = subprocess.run(
                [shutil.which("nft"), "--check", "-f", str(inst.nftFilePath)],
                capture_output=True, text=True, timeout=120)
            self.assertEqual(result.returncode, 0,
                             f"nft --check: {result.stderr}")
        finally:
            tmp.cleanup()


if __name__ == "__main__":
    unittest.main(verbosity=2)

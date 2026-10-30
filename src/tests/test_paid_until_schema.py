"""
Регрессионные тесты хранения срока оплаты (paid_until) и "Безлимита".

Проверяется:
1. Тип колонки paid_until — всегда generic DateTime (DashboardConfig.
   PeerPaymentsColumnType): MySQL TIMESTAMP ограничен 1970-2038 и
   отклонял бы бессрочную дату 9999-12-31; SQLite динамичен; PostgreSQL
   компилирует DateTime в TIMESTAMP WITHOUT TIME ZONE (не ограничен
   2038; заметка: верхний регистр db.DATETIME на PostgreSQL рендерится
   в несуществующий тип DATETIME и для этой колонки не используется);
2. createDatabase создаёт peers-таблицу с DateTime-колонкой оплаты;
3. EnsureDatabaseIntegrity: недостающие колонки добавляются с нужным
   типом; для исторических MySQL-таблиц с TIMESTAMP-колонкой
   выдаётся ALTER MODIFY ... DATETIME (данные переносятся, никаких
   DROP/DELETE/TRUNCATE); для SQLite менять тип не нужно;
   SQLite-миграция добавления колонок не теряет существующие строки;
4. Функциональный цикл на реальном SQLite-движке: установка "Безлимита",
   изменение, продление (Days и PaidUntil), снятие, вычисление статуса и
   остатка дней (unset/expiring/active/expired), DaysRemaining для
   "Безлимита" остаётся None, статус active.

Реальный MySQL/PostgreSQL-сервер локально недоступен: их поведение
проверено на уровне компиляции DDL (диалекты sqlalchemy) и конструкции
миграционного ALTER;runtime-поведение MySQL остаётся непроверенным.

Запуск из src/:  python -m unittest discover -s tests -v
"""
import datetime
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

SRC = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SRC))

import sqlalchemy
from sqlalchemy.dialects import mysql, postgresql, sqlite as sqliteDialect
from flask import Flask

from modules.DashboardConfig import DashboardConfig
from modules.DashboardPeerPayments import (
    ComputePaymentStatus, IsUnlimitedPaidUntil, NormalizePaidUntil,
    ParsePaidUntilInput, UNLIMITED_PAID_UNTIL_STR, UNLIMITED_PAID_UNTIL)
from modules.Peer import Peer
from modules.WireguardConfiguration import WireguardConfiguration

TODAY = datetime.datetime.now().replace(hour=0, minute=0, second=0, microsecond=0)


def makeDashboardConfigStub(engine):
    """DashboardConfig через __new__: используется только engine."""
    config = DashboardConfig.__new__(DashboardConfig)
    config.engine = engine
    return config


def makeConfigurationStub(dbFile: Path):
    """Конфигурация через __new__ с реальным SQLite-движком и настоящей
    схемой (createDatabase)."""
    engine = sqlalchemy.create_engine(f"sqlite:///{dbFile}")
    configuration = WireguardConfiguration.__new__(WireguardConfiguration)
    configuration.Name = "PayTest"
    configuration.Protocol = "wg"
    configuration.DashboardConfig = SimpleNamespace(
        GetConfig=lambda section, key: ("", "sqlite"),
        PeerPaymentsColumnType=DashboardConfig.PeerPaymentsColumnType)
    configuration.engine = engine
    configuration.metadata = sqlalchemy.MetaData()
    configuration.createDatabase("PayTest")
    configuration.AllPeerJobs = SimpleNamespace(searchJob=lambda a, b: [])
    configuration.AllPeerShareLinks = SimpleNamespace(getLink=lambda a, b: [])
    configuration.getPeers = lambda: None
    configuration.getStatus = lambda: False  # туннель не трогаем
    return configuration


def insertPeer(configuration, paidUntil=None, paymentComment="KeepComment"):
    values = {
        "id": "peerKey1",
        "private_key": "PEERPRIVATEKEY",
        "DNS": "1.1.1.1",
        "endpoint_allowed_ip": "0.0.0.0/0",
        "name": "TestPeer",
        "allowed_ip": "10.6.6.2/32",
        "mtu": 1420,
        "keepalive": 25,
        "notes": "OldNote",
        "remote_endpoint": "1.2.3.4",
        "preshared_key": "PSKKEY",
        "split_tunnel_ips": "",
        "split_tunnel_mode": "include",
        "telegram": "tg_handle",
        "paid_until": paidUntil,
        "payment_comment": paymentComment,
    }
    with configuration.engine.begin() as conn:
        conn.execute(configuration.peersTable.insert().values(values))
    return values


def fetchPeerRow(configuration, peerID="peerKey1"):
    with configuration.engine.connect() as conn:
        return conn.execute(
            configuration.peersTable.select().where(
                configuration.peersTable.columns.id == peerID)
        ).mappings().fetchone()


class PeerPaymentsColumnTypeTests(unittest.TestCase):
    """Тип колонки оплаты компилируется корректно во всех диалектах."""

    def test_type_instance(self):
        colType = DashboardConfig.PeerPaymentsColumnType()
        self.assertIsInstance(colType, sqlalchemy.DateTime)
        # Именно DateTime, а не MySQL-специфичный TIMESTAMP
        self.assertNotIsInstance(colType, sqlalchemy.TIMESTAMP)

    def test_ddl_sqlite_and_mysql_datetime(self):
        for dialectName, dialect, mustBe in (
                ("sqlite", sqliteDialect.dialect(), "DATETIME"),
                ("mysql", mysql.dialect(), "DATETIME")):
            compiled = DashboardConfig.PeerPaymentsColumnType().compile(
                dialect=dialect).upper()
            self.assertIn(mustBe, compiled, dialectName)
            self.assertNotIn("TIMESTAMP", compiled,
                             f"{dialectName}: TIMESTAMP запрещён для paid_until")

    def test_ddl_postgresql_not_limited(self):
        compiled = DashboardConfig.PeerPaymentsColumnType().compile(
            dialect=postgresql.dialect()).upper()
        # PostgreSQL: generic DateTime -> TIMESTAMP WITHOUT TIME ZONE,
        # диапазон дат до 294276 года - 9999-12-31 хранится. Обычный
        # db.DATETIME здесь нельзя: он рендерится в несуществующий тип
        # "DATETIME".
        self.assertIn("TIMESTAMP WITHOUT TIME ZONE", compiled)


class CreateDatabaseSchemaTests(unittest.TestCase):
    """Схема, которую создаёт createDatabase, пригодна для "Безлимита"."""

    def test_paid_until_column_is_datetime(self):
        tmp = tempfile.TemporaryDirectory()
        try:
            configuration = makeConfigurationStub(Path(tmp.name) / "db.db")
            columns = {c["name"]: c for c in sqlalchemy.inspect(
                configuration.engine).get_columns("PayTest")}
            self.assertIn("paid_until", columns)
            columnType = columns["paid_until"]["type"]
            self.assertIsInstance(columnType, sqlalchemy.DateTime)
            self.assertNotIsInstance(columnType, sqlalchemy.TIMESTAMP)
            # Остальные временные колонки не тронуты: time в transfer -
            # прежний с диалект-зависимый тип
            transferColumns = {c["name"]: c for c in sqlalchemy.inspect(
                configuration.engine).get_columns("PayTest_transfer")}
            self.assertIn("time", transferColumns)
        finally:
            configuration.engine.dispose()
            tmp.cleanup()


class EnsureMigrationsTests(unittest.TestCase):
    """EnsureDatabaseIntegrity: добавление колонок и миграция типа."""

    def setUp(self):
        self.app = Flask(__name__)

    def test_existing_sqlite_rows_and_missing_columns_added(self):
        """Существующая база старой схемы: колонки добавляются, строка
        данных (дата, комментарий) не теряется."""
        tmp = tempfile.TemporaryDirectory()
        engine = sqlalchemy.create_engine(f"sqlite:///{Path(tmp.name)}/db.db")
        try:
            oldTable = sqlalchemy.Table(
                "OldConf", sqlalchemy.MetaData(),
                sqlalchemy.Column('id', sqlalchemy.String(255), primary_key=True),
                sqlalchemy.Column('private_key', sqlalchemy.String(255)),
                sqlalchemy.Column('name', sqlalchemy.Text),
                sqlalchemy.Column('paid_until', sqlalchemy.TIMESTAMP))
            oldTable.create(engine)
            with engine.begin() as conn:
                conn.execute(oldTable.insert().values(
                    id="k1", private_key="AAA=", name="OldPeer",
                    paid_until=datetime.datetime(2026, 10, 1)))

            config = makeDashboardConfigStub(engine)
            with self.app.app_context():
                config.EnsureDatabaseIntegrity({"OldConf": object()})

            columns = {c["name"]: c for c in sqlalchemy.inspect(engine).get_columns("OldConf")}
            for required in ("paid_until", "payment_comment", "telegram"):
                self.assertIn(required, columns)
            # SQLite динамичен: объявленный в старой схеме тип (TIMESTAMP)
            # в отражении сохраняется - это допустимо, менять его не нужно.
            # Главное - данные строки не потеряны:
            with engine.connect() as conn:
                row = conn.execute(sqlalchemy.text(
                    'SELECT private_key, name, paid_until FROM "OldConf"')).fetchone()
            self.assertEqual((row[0], row[1]), ("AAA=", "OldPeer"))
            if isinstance(row[2], datetime.datetime):
                self.assertEqual(row[2], datetime.datetime(2026, 10, 1))
            else:
                self.assertIn("2026-10-01", str(row[2]))
        finally:
            engine.dispose()
            tmp.cleanup()

    def test_mysql_timestamp_column_migrated_to_datetime(self):
        """Историческая MySQL-схема: paid_until TIMESTAMP -> ALTER MODIFY
        DATETIME; только изменяющие тип выражения, данные не уничтожаются."""
        tmp = tempfile.TemporaryDirectory()
        engine = sqlalchemy.create_engine(f"sqlite:///{Path(tmp.name)}/db.db")
        try:
            oldTable = sqlalchemy.Table(
                "OldConf", sqlalchemy.MetaData(),
                sqlalchemy.Column('id', sqlalchemy.String(255), primary_key=True),
                sqlalchemy.Column('private_key', sqlalchemy.String(255)),
                sqlalchemy.Column('paid_until', sqlalchemy.TIMESTAMP))
            oldTable.create(engine)
            with engine.begin() as conn:
                conn.execute(oldTable.insert().values(
                    id="k1", private_key="AAA=", paid_until=datetime.datetime(2026, 10, 1)))

            executed = []

            class RecordingConn:
                def execute(self, statement):
                    executed.append(str(statement))
                    return None

                def __enter__(self):
                    return self

                def __exit__(self, excType, excValue, tb):
                    return False

            # Проверяем только генерацию ALTER: SQLite не умеет MODIFY,
            # поэтому реальное выполнение подменяем записью
            engine.begin = lambda: RecordingConn()
            engine.dialect.name = "mysql"

            config = makeDashboardConfigStub(engine)
            with self.app.app_context():
                config.EnsureDatabaseIntegrity({"OldConf": object()})

            self.assertGreater(len(executed), 0, "операторы должны формироваться")
            modifyStatements = [
                sql for sql in executed if "MODIFY" in sql.upper()]
            self.assertEqual(len(modifyStatements), 1,
                             f"ровно один MODIFY, получил: {executed}")
            modify = modifyStatements[0]
            self.assertIn("ALTER TABLE", modify)
            self.assertIn("paid_until", modify)
            self.assertIn("DATETIME", modify)
            # Никакие операторы этой процедуры не уничтожают данные.
            # Одиночные слова без завершающего пробела (например
            # payment_comment в имени колонки) не совпадают.
            for sql in executed:
                upper = sql.upper()
                for forbidden in ("DROP ", "DELETE ", "TRUNCATE ", "REPLACE ", "UPDATE "):
                    self.assertNotIn(forbidden, upper, sql)
            # Данные в базе не тронуты ни одним выражением
            with engine.connect() as conn:
                row = conn.execute(sqlalchemy.text(
                    'SELECT private_key, paid_until FROM "OldConf"')).fetchone()
            self.assertEqual(row[0], "AAA=")
            # На sqlite generic TIMESTAMP без result-процессора возвращает
            # исходную строку вставки; на дату платежа это не влияет,
            # важно, что данные не изменены.
            if isinstance(row[1], datetime.datetime):
                self.assertEqual(row[1], datetime.datetime(2026, 10, 1))
            else:
                self.assertEqual(str(row[1]), "2026-10-01 00:00:00.000000")
        finally:
            engine.dispose()
            tmp.cleanup()

    def test_datetime_column_not_migrated_again(self):
        """Если paid_until уже DATETIME - ALTER не формируется."""
        tmp = tempfile.TemporaryDirectory()
        try:
            configuration = makeConfigurationStub(Path(tmp.name) / "db.db")
            executed = []

            class RecordingConn:
                def execute(self, statement):
                    executed.append(str(statement))
                    return None

                def __enter__(self):
                    return self

                def __exit__(self, excType, excValue, tb):
                    return False

            configuration.engine.begin = lambda: RecordingConn()
            configuration.engine.dialect.name = "mysql"

            config = makeDashboardConfigStub(configuration.engine)
            with self.app.app_context():
                config.EnsureDatabaseIntegrity({"PayTest": object()})

            modifyStatements = [s for s in executed if "MODIFY" in s.upper()]
            self.assertEqual(modifyStatements, [])
        finally:
            configuration.engine.dispose()
            tmp.cleanup()

    def test_sqlite_never_migrates_column_type(self):
        """SQLite динамичен: миграции типа не выполняются совсем."""
        tmp = tempfile.TemporaryDirectory()
        try:
            configuration = makeConfigurationStub(Path(tmp.name) / "db.db")
            executed = []

            class RecordingConn:
                def execute(self, statement):
                    executed.append(str(statement))
                    return None

                def __enter__(self):
                    return self

                def __exit__(self, excType, excValue, tb):
                    return False

            configuration.engine.begin = lambda: RecordingConn()
            config = makeDashboardConfigStub(configuration.engine)
            with self.app.app_context():
                config.EnsureDatabaseIntegrity({"PayTest": object()})

            modifyStatements = [s for s in executed if "MODIFY" in s.upper()]
            self.assertEqual(modifyStatements, [])
        finally:
            configuration.engine.dispose()
            tmp.cleanup()


class UnlimitedPaymentSqliteTests(unittest.TestCase):
    """Установка/изменение/продление/снятие и статус на реальном SQLite."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.configuration = makeConfigurationStub(Path(self.tmp.name) / "db.db")
        insertPeer(self.configuration, paidUntil=None)

    def tearDown(self):
        self.configuration.engine.dispose()
        self.tmp.cleanup()

    def refreshedPeer(self):
        row = fetchPeerRow(self.configuration)
        return Peer(row, self.configuration)

    def updatePaidUntil(self, rawValue):
        peer = self.refreshedPeer()
        status, msg = peer.updatePeer(
            peer.name, peer.private_key, peer.preshared_key, peer.DNS,
            peer.allowed_ip, peer.endpoint_allowed_ip, peer.mtu,
            peer.keepalive, peer.notes, peer.split_tunnel_ips,
            peer.split_tunnel_mode, peer.telegram,
            rawValue, peer.payment_comment)
        return status, msg

    def test_unlimited_roundtrip_active_with_none_days(self):
        status, msg = self.updatePaidUntil(UNLIMITED_PAID_UNTIL_STR)
        self.assertTrue(status, msg)
        peer = self.refreshedPeer()
        row = fetchPeerRow(self.configuration)
        # В БД хранится datetime 9999-12-31, читается без потерь
        self.assertEqual(row["paid_until"], datetime.datetime(9999, 12, 31))
        self.assertTrue(IsUnlimitedPaidUntil(row["paid_until"]))
        self.assertEqual(peer.PaymentStatus, "active")
        self.assertIsNone(peer.DaysRemaining, "у безлимита не должно быть дней")
        self.assertEqual(peer.PaidUntilFormatted, UNLIMITED_PAID_UNTIL_STR)
        self.assertEqual(peer.payment_comment, "KeepComment")
        self.assertEqual(peer.notes, "OldNote")

    def test_set_plain_date_and_days_remaining(self):
        status, msg = self.updatePaidUntil(
            (TODAY + datetime.timedelta(days=40)).strftime("%Y-%m-%d"))
        self.assertTrue(status, msg)
        peer = self.refreshedPeer()
        self.assertEqual(peer.PaymentStatus, "active")
        self.assertEqual(peer.DaysRemaining, 40)

    def test_expiring_status(self):
        status, msg = self.updatePaidUntil(
            (TODAY + datetime.timedelta(days=3)).strftime("%Y-%m-%d"))
        self.assertTrue(status, msg)
        peer = self.refreshedPeer()
        self.assertEqual(peer.PaymentStatus, "expiring")
        self.assertEqual(peer.DaysRemaining, 3)

    def test_expired_status(self):
        self.updatePaidUntil(
            (TODAY - datetime.timedelta(days=2)).strftime("%Y-%m-%d"))
        peer = self.refreshedPeer()
        self.assertEqual(peer.PaymentStatus, "expired")
        self.assertEqual(peer.DaysRemaining, -2)

    def test_extend_plain_payment(self):
        self.updatePaidUntil(
            (TODAY + datetime.timedelta(days=10)).strftime("%Y-%m-%d"))
        peer = self.refreshedPeer()
        status, msg = peer.ExtendPayment(30)
        self.assertTrue(status, msg)
        row = fetchPeerRow(self.configuration)
        self.assertEqual(row["paid_until"], TODAY + datetime.timedelta(days=40))

    def test_extend_unlimited_keeps_unlimited(self):
        self.updatePaidUntil(UNLIMITED_PAID_UNTIL_STR)
        peer = self.refreshedPeer()
        status, msg = peer.ExtendPayment(30)
        self.assertTrue(status, msg)
        row = fetchPeerRow(self.configuration)
        self.assertEqual(row["paid_until"], datetime.datetime(9999, 12, 31))
        self.assertTrue(IsUnlimitedPaidUntil(row["paid_until"]))

    def test_unset_payment(self):
        self.updatePaidUntil(UNLIMITED_PAID_UNTIL_STR)
        status, msg = self.updatePaidUntil("")  # "снять срок"
        self.assertTrue(status, msg)
        row = fetchPeerRow(self.configuration)
        self.assertIsNone(row["paid_until"])
        peer = self.refreshedPeer()
        self.assertEqual(peer.PaymentStatus, "unset")

    def test_unlimited_input_parsing(self):
        parsed, err = ParsePaidUntilInput(UNLIMITED_PAID_UNTIL_STR)
        self.assertEqual(parsed, datetime.datetime(9999, 12, 31))
        self.assertIsNone(err)
        parsed, err = ParsePaidUntilInput("")
        self.assertIsNone(parsed)
        self.assertIsNone(err)


if __name__ == "__main__":
    unittest.main(verbosity=2)

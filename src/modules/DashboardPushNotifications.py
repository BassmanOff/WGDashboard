"""
Web Push Notifications (Web Push API + VAPID)

Нужны для того, чтобы администратор получал push на телефон, когда
истекает срок оплаты клиента. Работает только в secure context
(HTTPS) — это ограничение браузеров, а не панели.
"""
import json
import os

import sqlalchemy as db

from .DatabaseConnection import ConnectionString
from .DashboardLogger import DashboardLogger


class PushNotificationError(Exception):
    pass


class DashboardPushNotifications:
    def __init__(self, dashboardConfig, peerPayments):
        self.logger = DashboardLogger()
        self.dashboardConfig = dashboardConfig
        # Оплата отслеживается по пирам, поэтому источник - сводка по
        # оплатам пиров, а не учётные записи клиентов
        self.peerPayments = peerPayments
        self.engine = db.create_engine(ConnectionString("wgdashboard"))
        self.metadata = db.MetaData()
        timeType = (db.DATETIME if 'sqlite:///' in ConnectionString("wgdashboard") else db.TIMESTAMP)

        self.subscriptionTable = db.Table(
            'DashboardPushSubscriptions', self.metadata,
            db.Column('Endpoint', db.String(500), nullable=False, primary_key=True),
            db.Column('P256DH', db.String(255), nullable=False),
            db.Column('Auth', db.String(255), nullable=False),
            db.Column('UserAgent', db.Text),
            db.Column('Origin', db.String(255)),
            db.Column('CreatedDate', timeType, server_default=db.func.now()),
            db.Column('LastSuccess', timeType),
            db.Column('LastFailure', timeType),
            db.Column('FailureReason', db.Text),
            extend_existing=True
        )

        # VAPID-ключи генерируются один раз и хранятся в БД
        self.vapidTable = db.Table(
            'DashboardPushVapid', self.metadata,
            db.Column('ID', db.String(10), nullable=False, primary_key=True),
            db.Column('PrivateKey', db.Text, nullable=False),
            db.Column('PublicKey', db.Text, nullable=False),
            db.Column('CreatedDate', timeType, server_default=db.func.now()),
            extend_existing=True
        )
        self.metadata.create_all(self.engine)
        self.__migrateSubscriptionTable()
        self.__ensureVapidKeys()

    def __migrateSubscriptionTable(self):
        """create_all() не добавляет колонки в существующие таблицы."""
        expected = {
            'Origin': db.String(255),
            'LastSuccess': (db.DATETIME if 'sqlite:///' in ConnectionString("wgdashboard") else db.TIMESTAMP),
            'LastFailure': (db.DATETIME if 'sqlite:///' in ConnectionString("wgdashboard") else db.TIMESTAMP),
            'FailureReason': db.Text,
        }
        try:
            inspector = db.inspect(self.engine)
            if not inspector.has_table('DashboardPushSubscriptions'):
                return
            existing = [c['name'] for c in inspector.get_columns('DashboardPushSubscriptions')]
            with self.engine.begin() as conn:
                preparer = self.engine.dialect.identifier_preparer
                for col_name, col_type in expected.items():
                    if col_name in existing:
                        continue
                    type_str = col_type().compile(dialect=self.engine.dialect)
                    conn.execute(db.text(
                        f"ALTER TABLE {preparer.quote_identifier('DashboardPushSubscriptions')} "
                        f"ADD COLUMN {preparer.quote_identifier(col_name)} {type_str}"
                    ))
                    self.logger.log(
                        Message=f"Push table migration: added column '{col_name}'")
        except Exception as e:
            self.logger.log(Status="false", Message=f"Push table migration failed: {e}")

    # ---------------------------------------------------------------- VAPID

    def __ensureVapidKeys(self) -> tuple[str, str]:
        with self.engine.connect() as conn:
            row = conn.execute(
                self.vapidTable.select().where(self.vapidTable.c.ID == 'default')
            ).mappings().fetchone()
        if row is not None:
            return row['PrivateKey'], row['PublicKey']

        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.primitives import serialization

        privateKey = ec.generate_private_key(ec.SECP256R1())
        privatePem = privateKey.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ).decode('utf-8')
        publicPem = privateKey.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')

        with self.engine.begin() as conn:
            conn.execute(
                self.vapidTable.insert().values({
                    "ID": "default",
                    "PrivateKey": privatePem,
                    "PublicKey": publicPem
                })
            )
        self.logger.log(Message="Generated new VAPID keys for push notifications")
        return privatePem, publicPem

    def GetVapidPublicKey(self) -> str:
        """
        Публичный ключ для applicationServerKey.
        Браузер ожичает base64url от необработанной точки P-256
        (0x04 || X || Y, 65 байт), а не PEM — поэтому конвертируем.
        """
        import base64
        from cryptography.hazmat.primitives import serialization

        privatePem, _ = self.__ensureVapidKeys()
        privateKey = serialization.load_pem_private_key(
            privatePem.encode('utf-8'), password=None)
        rawPoint = privateKey.public_key().public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.UncompressedPoint
        )
        return base64.urlsafe_b64encode(rawPoint).decode('utf-8').rstrip('=')

    def __getVapidClaims(self, origin: str = None) -> dict:
        """
        sub — контакт администратора, aud — origin панели.
        Push-сервисы (FCM, Mozilla autopush) сверяют aud с origin подписки,
        поэтому origin сохраняется в момент подписки, а не вычисляется
        заново: в фоновом потоке объект request недоступен.
        """
        _, sendFrom = self.dashboardConfig.GetConfig("Email", "send_from")
        mailto = f"mailto:{sendFrom}" if sendFrom else "mailto:admin@localhost"

        claims = {"sub": mailto}
        if origin:
            claims["aud"] = origin
        else:
            try:
                from flask import request
                claims["aud"] = request.url_root.rstrip('/')
            except RuntimeError:
                # Фоновый поток без сохранённого origin: отправка невозможна
                raise PushNotificationError(
                    "No origin available for VAPID claims (subscription predates origin storage)")
        return claims

    # --------------------------------------------------------- Настройки

    # Допустимые интервалы проверки: 5 мин ... 7 суток
    INTERVAL_MIN = 300
    INTERVAL_MAX = 604800
    INTERVAL_PRESETS = [300, 900, 3600, 10800, 21600, 43200, 86400, 172800, 604800]

    @staticmethod
    def __clampInterval(value) -> int:
        """Приводит интервал к допустимому диапазону."""
        try:
            seconds = int(value)
        except (TypeError, ValueError):
            return 86400
        if seconds < DashboardPushNotifications.INTERVAL_MIN:
            return DashboardPushNotifications.INTERVAL_MIN
        if seconds > DashboardPushNotifications.INTERVAL_MAX:
            return DashboardPushNotifications.INTERVAL_MAX
        return seconds

    def GetCheckInterval(self) -> int:
        """Текущий интервал проверки в секундах."""
        _, value = self.dashboardConfig.GetConfig("Push", "check_interval")
        return self.__clampInterval(value)

    def GetExpiringDays(self) -> int:
        """За сколько дней предупреждать об истечении оплаты (0 = не предупреждать)."""
        _, value = self.dashboardConfig.GetConfig("Push", "expiring_days")
        try:
            days = int(value)
        except (TypeError, ValueError):
            return 7
        return max(0, min(days, 90))

    def GetSettings(self) -> dict:
        return {
            "check_interval": self.GetCheckInterval(),
            "check_interval_min": self.INTERVAL_MIN,
            "check_interval_max": self.INTERVAL_MAX,
            "check_interval_presets": self.INTERVAL_PRESETS,
            "expiring_days": self.GetExpiringDays(),
            "subscriptions": self.GetSubscriptionCount()
        }

    def UpdateSettings(self, check_interval=None, expiring_days=None) -> tuple[bool, str | None]:
        if check_interval is not None:
            try:
                seconds = int(check_interval)
            except (TypeError, ValueError):
                return False, "check_interval must be an integer number of seconds"
            if seconds < self.INTERVAL_MIN or seconds > self.INTERVAL_MAX:
                return False, (
                    f"check_interval must be between {self.INTERVAL_MIN} "
                    f"and {self.INTERVAL_MAX} seconds"
                )
            self.dashboardConfig.SetConfig("Push", "check_interval", str(seconds))

        if expiring_days is not None:
            try:
                days = int(expiring_days)
            except (TypeError, ValueError):
                return False, "expiring_days must be an integer"
            if days < 0 or days > 90:
                return False, "expiring_days must be between 0 and 90"
            self.dashboardConfig.SetConfig("Push", "expiring_days", str(days))

        self.logger.log(Message=f"Push settings updated: {self.GetSettings()}")
        return True, None

    # --------------------------------------------------------- Подписки

    def Subscribe(self, endpoint: str, p256dh: str, auth: str, userAgent: str = "",
                  origin: str = "") -> tuple[bool, str | None]:
        if not all([endpoint, p256dh, auth]):
            return False, "endpoint, p256dh and auth are required"
        if not endpoint.startswith("https://"):
            return False, "endpoint must be a valid https URL"
        try:
            with self.engine.begin() as conn:
                existing = conn.execute(
                    self.subscriptionTable.select().where(
                        self.subscriptionTable.c.Endpoint == endpoint
                    )
                ).mappings().fetchone()
                values = {
                    "P256DH": p256dh,
                    "Auth": auth,
                    "UserAgent": (userAgent or "")[:1000],
                    "Origin": (origin or "")[:255],
                    "LastFailure": None,
                    "FailureReason": None
                }
                if existing is None:
                    conn.execute(self.subscriptionTable.insert().values(
                        {"Endpoint": endpoint, **values}))
                else:
                    conn.execute(
                        self.subscriptionTable.update().values(values).where(
                            self.subscriptionTable.c.Endpoint == endpoint))
        except Exception as e:
            return False, f"Failed to store subscription: {e}"
        self.logger.log(Message=f"Push subscription registered ({endpoint[:60]}...)")
        return True, None

    def Unsubscribe(self, endpoint: str) -> tuple[bool, str | None]:
        if not endpoint:
            return False, "endpoint is required"
        try:
            with self.engine.begin() as conn:
                conn.execute(
                    self.subscriptionTable.delete().where(
                        self.subscriptionTable.c.Endpoint == endpoint))
        except Exception as e:
            return False, str(e)
        return True, None

    def GetSubscriptionCount(self) -> int:
        with self.engine.connect() as conn:
            return len(conn.execute(self.subscriptionTable.select()).fetchall())

    # ------------------------------------------------------------ Отправка

    def __getPywebpush(self):
        try:
            from pywebpush import webpush
            return webpush
        except ImportError as e:
            raise PushNotificationError(
                "pywebpush is not installed. Run: pip install pywebpush"
            ) from e

    def __sendOne(self, webpush, subscription: dict, payload: str) -> tuple[bool, str | None]:
        import datetime
        privateKey, _ = self.__ensureVapidKeys()
        try:
            webpush(
                subscription_info={
                    "endpoint": subscription['Endpoint'],
                    "keys": {
                        "p256dh": subscription['P256DH'],
                        "auth": subscription['Auth']
                    }
                },
                data=payload,
                vapid_private_key=privateKey,
                vapid_claims=self.__getVapidClaims(subscription.get('Origin')),
                ttl=86400,
                timeout=15
            )
            with self.engine.begin() as conn:
                conn.execute(
                    self.subscriptionTable.update().values({
                        "LastSuccess": datetime.datetime.now(),
                        "LastFailure": None,
                        "FailureReason": None
                    }).where(self.subscriptionTable.c.Endpoint == subscription['Endpoint'])
                )
            return True, None
        except Exception as e:
            # 404/410 — endpoint больше не существует, подписку надо удалить
            status = getattr(e, 'response', None)
            code = getattr(status, 'status_code', None)
            reason = str(e)
            expired = code in (404, 410)
            try:
                with self.engine.begin() as conn:
                    if expired:
                        conn.execute(
                            self.subscriptionTable.delete().where(
                                self.subscriptionTable.c.Endpoint == subscription['Endpoint'])
                        )
                    else:
                        conn.execute(
                            self.subscriptionTable.update().values({
                                "LastFailure": datetime.datetime.now(),
                                "FailureReason": reason[:1000]
                            }).where(self.subscriptionTable.c.Endpoint == subscription['Endpoint'])
                        )
            except Exception as dbError:
                self.logger.log(Status="false",
                                Message=f"Failed to update push subscription state: {dbError}")
            if expired:
                self.logger.log(Message=f"Removed expired push subscription (HTTP {code})")
            else:
                self.logger.log(Status="false",
                                Message=f"Push delivery failed: {reason[:200]}")
            return False, reason

    def SendToAll(self, title: str, body: str, url: str = None, tag: str = "wgd") -> dict:
        """Рассылает уведомление всем подписанным устройствам."""
        result = {"sent": 0, "failed": 0, "removed": 0, "error": None}
        if self.GetSubscriptionCount() == 0:
            result["error"] = "No push subscriptions"
            return result
        try:
            webpush = self.__getPywebpush()
        except PushNotificationError as e:
            result["error"] = str(e)
            return result

        payload = json.dumps({
            "title": title,
            "body": body,
            "url": url or "./clients",
            "tag": tag
        }, ensure_ascii=False)

        with self.engine.connect() as conn:
            subscriptions = [dict(x) for x in conn.execute(
                self.subscriptionTable.select()).mappings().fetchall()]

        for s in subscriptions:
            ok, reason = self.__sendOne(webpush, s, payload)
            if ok:
                result["sent"] += 1
            else:
                result["failed"] += 1
                if "404" in (reason or "") or "410" in (reason or ""):
                    result["removed"] += 1
        return result

    def SendPaymentReminders(self, expiringDays: int = None) -> dict:
        """
        Проверяет пиры и уведомляет администратора о просроченных.
        Отправка выполняется только при смене состояния (вызывающий код
        сравнивает хеш), поэтому повторов при каждом цикле не будет.
        """
        result = {"sent": 0, "failed": 0, "error": None, "notified": []}
        if expiringDays is None:
            expiringDays = self.GetExpiringDays()
        overdue = self.peerPayments.GetOverduePeers()
        expiring = self.peerPayments.GetExpiringPeers(expiringDays)
        if len(overdue) == 0 and len(expiring) == 0:
            return result

        lines = []
        for c in overdue:
            name = c.get('name') or c.get('id')
            tg = c.get('telegram')
            days = abs(c.get('DaysRemaining') or 0)
            contact = f" ({tg})" if tg else ""
            lines.append(f"{name}{contact} — просрочка {days} дн.")
        for c in expiring:
            name = c.get('name') or c.get('id')
            lines.append(f"{name} — истекает через {c.get('DaysRemaining')} дн.")

        title = "WGDashboard: оплата"
        if len(overdue) > 0:
            body = (f"Просрочено: {len(overdue)}\n" + "\n".join(lines[:8])
                    + ("\n..." if len(lines) > 8 else ""))
        else:
            body = f"Скоро истекает: {len(expiring)}\n" + "\n".join(lines[:8])

        # Ссылка ведёт в конфигурацию, где живут пиры, а не в раздел
        # клиентов: оплата теперь отслеживается по пирам
        result = self.SendToAll(title, body, url="./", tag="wgd-payment")
        result["notified"] = [c.get('id') for c in overdue]
        return result

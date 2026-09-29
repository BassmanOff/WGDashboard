"""
Расчёт состояния оплаты для пира.

Логика вынесена отдельно, потому что её используют три места: объект
Peer (для выдачи в API), сводка по всем конфигурациям и push-уведомления.
Раньше расчёт жил в DashboardClients и был привязан к учётной записи
клиента, но клиент и пир - разные сущности: пир может существовать без
клиента, и наоборот. Для администратора важнее пир, поэтому состояние
считается по пиру.

Статусы:
  unset    - срок не задан
  active   - оплачено, до истечения больше порога
  expiring - срок заканчивается (по умолчанию <= 7 дней)
  expired  - просрочено
"""
import datetime
from typing import Any

# Срок считается истёкшим в конце указанного дня
EXPIRING_WITHIN_DAYS = 7


def NormalizePaidUntil(value: Any) -> datetime.datetime | None:
    """
    Приводит значение из БД к datetime или None.

    Нужно, потому что приходят как datetime (sqlite), так и строки
    разных форматов, в том числе из JSON-источников.
    """
    if value is None or value == "":
        return None
    if isinstance(value, datetime.datetime):
        return value
    if isinstance(value, datetime.date):
        return datetime.datetime(value.year, value.month, value.day)
    if isinstance(value, str):
        text = value.strip()
        if len(text) == 0:
            return None
        for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d"):
            try:
                return datetime.datetime.strptime(text[:19], fmt)
            except ValueError:
                continue
    return None


def ComputePaymentStatus(paidUntil: Any) -> tuple[str, int | None, str | None]:
    """
    Возвращает (PaymentStatus, DaysRemaining, PaidUntilFormatted).
    """
    parsed = NormalizePaidUntil(paidUntil)
    if parsed is None:
        return "unset", None, None
    today = datetime.datetime.now().replace(hour=0, minute=0, second=0, microsecond=0)
    days = (parsed.date() - today.date()).days
    if days < 0:
        status = "expired"
    elif days <= EXPIRING_WITHIN_DAYS:
        status = "expiring"
    else:
        status = "active"
    return status, days, parsed.strftime("%Y-%m-%d")


def ParsePaidUntilInput(value: Any) -> tuple[datetime.datetime | None, str | None]:
    """
    Разбирает дату, введённую администратором.

    Пустая строка означает "сбросить срок" и возвращает (None, None).
    """
    if value is None or (isinstance(value, str) and value.strip() == ""):
        return None, None
    if isinstance(value, str):
        value = value.strip()
        for fmt in ("%Y-%m-%d", "%Y-%m-%d %H:%M:%S"):
            try:
                return datetime.datetime.strptime(value[:19], fmt), None
            except ValueError:
                continue
        return None, "Paid until must be in YYYY-MM-DD format"
    return None, "Paid until must be in YYYY-MM-DD format"

"""
Сводка по оплатам на уровне пиров.

Собран из логики DashboardClients (PaymentStatus/DaysRemaining,
ExtendClientPayment, GetOverdueClients), но источник данных - пиры, а не
учётные записи клиентов. Причина: пир может существовать без клиента, и
для администратора "клиент" - это конкретный VPN-пир. Push-уведомления и
бейджи в списке читают состояние отсюда.
"""
import datetime
from typing import Any

from flask import current_app

from .DashboardPeerPayments import ComputePaymentStatus, NormalizePaidUntil


class DashboardPeerPayments:
    def __init__(self, wireguardConfigurations, dashboardConfig):
        self.wireguardConfigurations = wireguardConfigurations
        self.dashboardConfig = dashboardConfig

    # ------------------------------------------------------------------
    # Сводка
    # ------------------------------------------------------------------

    def GetAllPeerPayments(self) -> list[dict[str, Any]]:
        """
        Плоский список пиров с рассчитанным состоянием оплаты.

        Собирается каждый раз: пиры обновляются из файла конфигурации и из
        БД, поэтому держать копию значило бы кэшировать устаревающее.
        """
        result = []
        for name, configuration in self.wireguardConfigurations.items():
            try:
                peers = configuration.getPeersList()
            except Exception as e:
                current_app.logger.error(
                    f"PeerPayments: could not read peers of {name}: {e}")
                continue
            for p in peers:
                status, daysRemaining, paidUntilFormatted = ComputePaymentStatus(
                    p.paid_until)
                result.append({
                    "configuration": name,
                    "id": p.id,
                    "name": p.name,
                    "telegram": p.telegram,
                    "notes": p.notes,
                    "payment_comment": p.payment_comment,
                    "paid_until": paidUntilFormatted,
                    "PaymentStatus": status,
                    "DaysRemaining": daysRemaining,
                    "PaidUntilFormatted": paidUntilFormatted
                })
        return result

    def GetOverduePeers(self) -> list[dict[str, Any]]:
        return [p for p in self.GetAllPeerPayments()
                if p["PaymentStatus"] == "expired"]

    def GetExpiringPeers(self, withinDays: int) -> list[dict[str, Any]]:
        return [p for p in self.GetAllPeerPayments()
                if p["PaymentStatus"] == "expiring"
                and (p["DaysRemaining"] or 0) <= withinDays]

    def GetOverdueCount(self) -> int:
        return len(self.GetOverduePeers())

    def GetStateHash(self) -> str:
        """
        Хеш состояния для отправки уведомления только при смене.

        Без этого фоновая задача слала бы одно и то же уведомление на
        каждом цикле.
        """
        rows = sorted(
            (p["configuration"], p["id"], p["PaymentStatus"],
             str(p["DaysRemaining"]))
            for p in self.GetAllPeerPayments()
            if p["PaymentStatus"] in ("expired", "expiring"))
        return "|".join(":".join(str(x) for x in row) for row in rows)

    # ------------------------------------------------------------------
    # Изменение
    # ------------------------------------------------------------------

    def _findPeer(self, configName: str, peerID: str):
        if configName not in self.wireguardConfigurations.keys():
            return None, "Configuration does not exist"
        found, peer = self.wireguardConfigurations[configName].searchPeer(peerID)
        if not found:
            return None, "Peer does not exist"
        return peer, None

    def UpdatePeerPayment(self, configName: str, peerID: str, Days: int = None,
                          PaidUntil: str = None) -> tuple[bool, Any]:
        """
        Продлевает оплату на Days дней либо задаёт дату напрямую.

        Срок не затрагивает туннель, поэтому вызов awg не выполняется -
        соединение клиента не прерывается.
        """
        peer, err = self._findPeer(configName, peerID)
        if peer is None:
            return False, err
        if Days is not None:
            return peer.ExtendPayment(Days)
        if PaidUntil is not None:
            # updatePeer сам разберёт дату и запишет её; остальные поля
            # передаются текущие, поэтому VPN-параметры не меняются
            status, msg = peer.updatePeer(
                peer.name, peer.private_key, peer.preshared_key, peer.DNS,
                peer.allowed_ip, peer.endpoint_allowed_ip, peer.mtu,
                peer.keepalive, peer.notes, peer.split_tunnel_ips,
                peer.split_tunnel_mode, peer.telegram,
                PaidUntil, peer.payment_comment)
            if not status:
                return False, msg
            _, refreshed = self.wireguardConfigurations[configName].searchPeer(peerID)
            return True, refreshed.toJson()
        return False, "Either Days or PaidUntil must be provided"

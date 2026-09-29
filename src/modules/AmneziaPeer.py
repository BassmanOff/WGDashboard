from .Peer import Peer


class AmneziaPeer(Peer):
    def __init__(self, tableData, configuration):
        super().__init__(tableData, configuration)


    def updatePeer(self, name: str, private_key: str,
                   preshared_key: str,
                   dns_addresses: str,
                   allowed_ip: str,
                   endpoint_allowed_ip: str,
                   mtu: int,
                   keepalive: int,
                   notes: str,
                   split_tunnel_ips: str = "",
                   split_tunnel_mode: str = "include",
                   telegram: str = "",
                   paid_until: str = None,
                   payment_comment: str = ""
                   ) -> tuple[bool, str | None]:
        """
        Реализация НЕ дублирует Peer.updatePeer.

        В базовом классе все команды строятся через
        self.configuration.Protocol, который для AmneziaWG равен 'awg',
        поэтому отдельная копия метода не давала ничего, кроме риска
        разойтись с базовой - именно это и происходило: правки на оплату
        и откат записей в базовом классе до awg не доходили.
        """
        return super().updatePeer(
            name, private_key, preshared_key, dns_addresses, allowed_ip,
            endpoint_allowed_ip, mtu, keepalive, notes,
            split_tunnel_ips, split_tunnel_mode, telegram,
            paid_until, payment_comment)

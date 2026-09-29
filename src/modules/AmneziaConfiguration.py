"""
AmneziaWG Configuration (v3.1+)
"""
import sqlalchemy, re
from flask import current_app
from .PeerJobs import PeerJobs
from .AmneziaPeer import AmneziaPeer
from .PeerShareLinks import PeerShareLinks
from .Utilities import RegexMatch
from .WireguardConfiguration import WireguardConfiguration
from .DashboardWebHooks import DashboardWebHooks


class AmneziaConfiguration(WireguardConfiguration):
    # AmneziaWG 3.1 default values
    DEFAULT_HEADER_PROTECTION_KEY = ""
    DEFAULT_CONTENT_PADDING_ADDITION = "0"
    DEFAULT_REKEY_AFTER_TIME = "0"
    DEFAULT_REKEY_TIMEOUT = "0"
    DEFAULT_REJECT_AFTER_TIME = "0"
    DEFAULT_KEEPALIVE_TIMEOUT = "0"
    DEFAULT_MAX_HANDSHAKE_ATTEMPTS = "0"
    DEFAULT_RANDOM_TRAILERS = "off"
    DEFAULT_DISABLE_COOKIES = "off"

    def __init__(self,
                 DashboardConfig,
                 AllPeerJobs: PeerJobs,
                 AllPeerShareLinks: PeerShareLinks,
                 DashboardWebHooks: DashboardWebHooks,
                 name: str = None,
                 data: dict = None,
                 backup: dict = None,
                 startup: bool = False):
        # AmneziaWG 2.0+ parameters
        self.Jc = 0
        self.Jmin = 0
        self.Jmax = 0
        self.S1 = 0
        self.S2 = 0
        self.S3 = 0
        self.S4 = 0
        self.H1 = 1
        self.H2 = 2
        self.H3 = 3
        self.H4 = 4
        self.I1 = "0"
        self.I2 = "0"
        self.I3 = "0"
        self.I4 = "0"
        self.I5 = "0"

        # AmneziaWG 3.1 new parameters
        self.HeaderProtectionKey = self.DEFAULT_HEADER_PROTECTION_KEY
        self.ContentPaddingAddition = self.DEFAULT_CONTENT_PADDING_ADDITION
        self.RekeyAfterTime = self.DEFAULT_REKEY_AFTER_TIME
        self.RekeyTimeout = self.DEFAULT_REKEY_TIMEOUT
        self.RejectAfterTime = self.DEFAULT_REJECT_AFTER_TIME
        self.KeepaliveTimeout = self.DEFAULT_KEEPALIVE_TIMEOUT
        self.MaxHandshakeAttempts = self.DEFAULT_MAX_HANDSHAKE_ATTEMPTS
        self.RandomTrailers = self.DEFAULT_RANDOM_TRAILERS
        self.DisableCookies = self.DEFAULT_DISABLE_COOKIES

        super().__init__(DashboardConfig, AllPeerJobs, AllPeerShareLinks, DashboardWebHooks, name, data, backup, startup, wg=False)

    def toJson(self):
        self.Status = self.getStatus()
        return {
            "Status": self.Status,
            "Name": self.Name,
            "PrivateKey": self.PrivateKey,
            "PublicKey": self.PublicKey,
            "Address": self.Address,
            "ListenPort": self.ListenPort,
            "PreUp": self.PreUp,
            "PreDown": self.PreDown,
            "PostUp": self.PostUp,
            "PostDown": self.PostDown,
            "SaveConfig": self.SaveConfig,
            "Info": self.configurationInfo.model_dump(),
            "DataUsage": {
                "Total": sum(list(map(lambda x: x.cumu_data + x.total_data, self.Peers))),
                "Sent": sum(list(map(lambda x: x.cumu_sent + x.total_sent, self.Peers))),
                "Receive": sum(list(map(lambda x: x.cumu_receive + x.total_receive, self.Peers)))
            },
            "ConnectedPeers": len(list(filter(lambda x: x.status == "running", self.Peers))),
            "TotalPeers": len(self.Peers),
            "Protocol": self.Protocol,
            "Table": self.Table,
            # AmneziaWG 2.0+ parameters
            "Jc": self.Jc,
            "Jmin": self.Jmin,
            "Jmax": self.Jmax,
            "S1": self.S1,
            "S2": self.S2,
            "S3": self.S3,
            "S4": self.S4,
            "H1": self.H1,
            "H2": self.H2,
            "H3": self.H3,
            "H4": self.H4,
            "I1": self.I1,
            "I2": self.I2,
            "I3": self.I3,
            "I4": self.I4,
            "I5": self.I5,
            # AmneziaWG 3.1 new parameters
            "HeaderProtectionKey": self.HeaderProtectionKey,
            "ContentPaddingAddition": self.ContentPaddingAddition,
            "RekeyAfterTime": self.RekeyAfterTime,
            "RekeyTimeout": self.RekeyTimeout,
            "RejectAfterTime": self.RejectAfterTime,
            "KeepaliveTimeout": self.KeepaliveTimeout,
            "MaxHandshakeAttempts": self.MaxHandshakeAttempts,
            "RandomTrailers": self.RandomTrailers,
            "DisableCookies": self.DisableCookies
        }

    def createDatabase(self, dbName = None):
        """
        Схема таблиц для AmneziaWG полностью совпадает с базовым классом -
        протокол влияет только на содержимое .conf, но не на структуру БД.

        Раньше здесь была отдельная копия списка колонок, которая разошлась
        с базовой: колонки split_tunnel_* и telegram появились только в
        базовой, а SQLAlchemy строил insert по списку из этого метода и
        падал с 'Unconsumed column names'. Ранье это давало 'Internal
        server error' вместо понятного сообщения.
        """
        return super().createDatabase(dbName)

    def getPeers(self):
        """
        Разбор .conf идентичен базовому классу: протокол не меняет формат
        секций [Peer]. Отличие одно - создаётся AmneziaPeer, у которого
        updatePeer умеет работать с параметрами AmneziaWG.

        Раньше здесь была вторая копия этого метода, которая со временем
        разошлась с базовой (свой список колонок, своя обработка ошибок),
        поэтому изменения в базовом классе до awg не доходили.
        """
        self.Peers.clear()
        if self.configurationFileChanged():
            with open(self.configPath, 'r') as configFile:
                p = []
                pCounter = -1
                content = configFile.read().split('\n')
                try:
                    if "[Peer]" not in content:
                        current_app.logger.info(f"{self.Name} config has no [Peer] section")
                        return

                    peerStarts = content.index("[Peer]")
                    content = content[peerStarts:]
                    for i in content:
                        if not RegexMatch("#(.*)", i) and not RegexMatch(";(.*)", i):
                            if i == "[Peer]":
                                pCounter += 1
                                p.append({})
                                p[pCounter]["name"] = ""
                            else:
                                if len(i) > 0:
                                    split = re.split(r'\s*=\s*', i, 1)
                                    if len(split) == 2:
                                        p[pCounter][split[0]] = split[1]

                        if RegexMatch("#Name# = (.*)", i):
                            split = re.split(r'\s*=\s*', i, 1)
                            if len(split) == 2:
                                p[pCounter]["name"] = split[1]
                    with self.engine.begin() as conn:
                        for i in p:
                            if "PublicKey" in i.keys():
                                tempPeer = conn.execute(self.peersTable.select().where(
                                    self.peersTable.columns.id == i['PublicKey']
                                )).mappings().fetchone()
                                if tempPeer is None:
                                    tempPeer = {
                                        "id": i['PublicKey'],
                                        "private_key": "",
                                        "DNS": self.DashboardConfig.GetConfig("Peers", "peer_global_DNS")[1],
                                        "endpoint_allowed_ip": self.DashboardConfig.GetConfig("Peers", "peer_endpoint_allowed_ip")[1],
                                        "name": i.get("name"),
                                        "total_receive": 0,
                                        "total_sent": 0,
                                        "total_data": 0,
                                        "endpoint": "N/A",
                                        "status": "stopped",
                                        "latest_handshake": "N/A",
                                        "allowed_ip": i.get("AllowedIPs", "N/A"),
                                        "cumu_receive": 0,
                                        "cumu_sent": 0,
                                        "cumu_data": 0,
                                        "mtu": self.DashboardConfig.GetConfig("Peers", "peer_mtu")[1],
                                        "keepalive": self.DashboardConfig.GetConfig("Peers", "peer_keep_alive")[1],
                                        "notes": "",
                                        "telegram": "",
                                        "paid_until": None,
                                        "payment_comment": "",
                                        "remote_endpoint": self.DashboardConfig.GetConfig("Peers", "remote_endpoint")[1],
                                        "preshared_key": i["PresharedKey"] if "PresharedKey" in i.keys() else "",
                                        "split_tunnel_ips": "",
                                        "split_tunnel_mode": "include"
                                    }
                                    conn.execute(
                                        self.peersTable.insert().values(tempPeer)
                                    )
                                else:
                                    conn.execute(
                                        self.peersTable.update().values({
                                            "allowed_ip": i.get("AllowedIPs", "N/A")
                                        }).where(
                                            self.peersTable.columns.id == i['PublicKey']
                                        )
                                    )
                                self.Peers.append(AmneziaPeer(tempPeer, self))
                except Exception as e:
                    current_app.logger.error(f"{self.Name} getPeers() Error", e)
        else:
            with self.engine.connect() as conn:
                existingPeers = conn.execute(self.peersTable.select()).mappings().fetchall()
                for i in existingPeers:
                    self.Peers.append(AmneziaPeer(i, self))

    def addPeers(self, peers: list) -> tuple[bool, list, str]:
        """
        Создание пиров для AmneziaWG.

        Реализация намеренно НЕ дублирует WireguardConfiguration.addPeers:
        уникальной для awg тут только вызов self.Protocol в командах, а
        self.Protocol уже равен 'awg' у базового класса. Раньше здесь была
        отдельная копия метода, из-за чего исправления в базовом классе
        (передача реальной ошибки вместо 'Internal server error', откат
        записей БД при сбое) до awg не доходили.
        """
        return super().addPeers(peers)

    def getRestrictedPeers(self):
        self.RestrictedPeers = []
        with self.engine.connect() as conn:
            restricted = conn.execute(self.peersRestrictedTable.select()).mappings().fetchall()
            for i in restricted:
                self.RestrictedPeers.append(AmneziaPeer(i, self))

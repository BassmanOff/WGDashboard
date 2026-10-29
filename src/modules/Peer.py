"""
Peer
"""
import base64
import datetime
import json
import os, subprocess, uuid, random, re, ipaddress, zlib, struct
from datetime import timedelta

import jinja2
import sqlalchemy as db
from .PeerJob import PeerJob
from  flask import current_app
from .PeerShareLink import PeerShareLink
from .DashboardPeerPayments import ComputePaymentStatus, IsUnlimitedPaidUntil, ParsePaidUntilInput
from .Utilities import GenerateWireguardPublicKey, CheckAddress, ValidateDNSAddress, ValidateSplitTunnelList


class Peer:
    def __init__(self, tableData, configuration):
        self.configuration = configuration
        self.id = tableData["id"]
        self.private_key = tableData["private_key"]
        self.DNS = tableData["DNS"]
        self.endpoint_allowed_ip = tableData["endpoint_allowed_ip"]
        self.name = tableData["name"]
        self.total_receive = tableData["total_receive"]
        self.total_sent = tableData["total_sent"]
        self.total_data = tableData["total_data"]
        self.endpoint = tableData["endpoint"]
        self.status = tableData["status"]
        self.latest_handshake = tableData["latest_handshake"]
        self.allowed_ip = tableData["allowed_ip"]
        self.cumu_receive = tableData["cumu_receive"]
        self.cumu_sent = tableData["cumu_sent"]
        self.cumu_data = tableData["cumu_data"]
        self.mtu = tableData["mtu"]
        self.keepalive = tableData["keepalive"]
        self.notes = tableData.get("notes", "")
        self.remote_endpoint = tableData["remote_endpoint"]
        self.preshared_key = tableData["preshared_key"]
        # Split tunneling fields.
        # Колонки добавляются миграцией ALTER TABLE без DEFAULT, поэтому в
        # существующих строках там NULL, а не отсутствующий ключ: get() с
        # дефолтом отдаёт None и проверка режима отклоняет пира. Поэтому
        # None приводится к значению по умолчанию явно.
        self.split_tunnel_ips = tableData.get("split_tunnel_ips") or ""
        self.split_tunnel_mode = tableData.get("split_tunnel_mode") or "include"
        # Контакт администратора, виден в списке пиров и его настройках
        self.telegram = tableData.get("telegram") or ""
        # Трекер оплаты. Срок и статус считаются на пире, потому что пир
        # может существовать без учётной записи клиента, а для админа
        # "клиент" - это именно пир.
        self.paid_until = tableData.get("paid_until")
        self.payment_comment = tableData.get("payment_comment") or ""
        status, daysRemaining, paidUntilFormatted = ComputePaymentStatus(self.paid_until)
        self.PaymentStatus = status
        self.DaysRemaining = daysRemaining
        self.PaidUntilFormatted = paidUntilFormatted
        self.jobs: list[PeerJob] = []
        self.ShareLink: list[PeerShareLink] = []
        self.getJobs()
        self.getShareLink()

    def toJson(self):
        # self.getJobs()
        # self.getShareLink()
        return self.__dict__

    def __repr__(self):
        return str(self.toJson())

    def updatePeer(self, name: str,
                   private_key: str,
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

        parsedPaidUntil, paidErr = ParsePaidUntilInput(paid_until)
        if paidErr:
            return False, paidErr

        # Данные администратора (имя, заметки, контакт, оплата) к VPN
        # отношения не имеют, поэтому при их изменении вызов awg не
        # нужен. Иначе продление оплаты рвало бы туннель и вызывало лишний
        # handshake. Поле name попадает в .conf как комментарий, но само по
        # себе awg не меняет, поэтому тоже не считается.
        #
        # Разделение на серверную и клиентскую части. В awg уходят только
        # AllowedIPs и PresharedKey (см. __runAwgUpdate). private_key, DNS,
        # endpoint_allowed_ip, MTU, keepalive и раздельное туннелирование
        # существуют только в конфиге, который получает клиент. Раньше они
        # тоже считались поводом вызвать awg, из-за чего обычная правка MTU
        # или Allowed IPs рвала туннель лишней командой "awg-quick save".
        serverChanged = (allowed_ip != self.allowed_ip
                         or preshared_key != self.preshared_key)

        clientChanged = (private_key != self.private_key
                         or dns_addresses != self.DNS
                         or endpoint_allowed_ip != self.endpoint_allowed_ip
                         or str(mtu) != str(self.mtu)
                         or str(keepalive) != str(self.keepalive)
                         or split_tunnel_ips != self.split_tunnel_ips
                         or split_tunnel_mode != self.split_tunnel_mode)

        if serverChanged or clientChanged:
            status, startMsg = self.__runAwgUpdate(
                private_key, preshared_key, dns_addresses, allowed_ip,
                endpoint_allowed_ip, mtu, keepalive,
                split_tunnel_ips, split_tunnel_mode,
                applyToServer=serverChanged)
            if not status:
                return False, startMsg

        values = {
            "name": name,
            "notes": notes,
            "telegram": telegram.strip(),
            "paid_until": parsedPaidUntil,
            "payment_comment": payment_comment
        }
        if serverChanged or clientChanged:
            values.update({
                "private_key": private_key,
                "DNS": dns_addresses,
                "endpoint_allowed_ip": endpoint_allowed_ip,
                "mtu": mtu,
                "keepalive": keepalive,
                "preshared_key": preshared_key,
                "split_tunnel_ips": split_tunnel_ips,
                "split_tunnel_mode": split_tunnel_mode
            })
        with self.configuration.engine.begin() as conn:
            conn.execute(
                self.configuration.peersTable.update().values(values).where(
                    self.configuration.peersTable.c.id == self.id
                )
            )
        self.configuration.getPeers()
        return True, None

    def ExtendPayment(self, Days: int) -> tuple[bool, str | None]:
        """
        Продлевает срок оплаты на Days дней, не трогая туннель.

        Возвращает только флаг и сообщение: актуальное состояние вызывающий
        код читает через searchPeer после refresh, потому что getPeers()
        пересобирает весь список.
        """
        if not isinstance(Days, int) or Days < 1 or Days > 3650:
            return False, "Days must be an integer between 1 and 3650"
        # "Безлимит" уже оплачен навсегда: продлевать нечего, а прибавление
        # timedelta к дате 9999-12-31 поднимает OverflowError. Возвращаем
        # успех без записи, чтобы кнопка "Продлить" не выглядела сломанной.
        if IsUnlimitedPaidUntil(self.paid_until):
            return True, None
        base = self.paid_until
        if base is None:
            base = datetime.datetime.now().replace(hour=0, minute=0, second=0, microsecond=0)
        newDate = base + datetime.timedelta(days=Days)
        with self.configuration.engine.begin() as conn:
            conn.execute(
                self.configuration.peersTable.update().values({
                    "paid_until": newDate
                }).where(
                    self.configuration.peersTable.c.id == self.id
                )
            )
        self.configuration.getPeers()
        return True, None

    def __runAwgUpdate(self, private_key, preshared_key, dns_addresses,
                       allowed_ip, endpoint_allowed_ip, mtu, keepalive,
                       split_tunnel_ips, split_tunnel_mode,
                       applyToServer: bool = True) -> tuple[bool, str | None]:
        """
        Валидация изменений и, при applyToServer, их применение через awg.

        Валидация выполняется всегда: она не зависит от того, меняем ли мы
        серверную часть. А команда awg выполняется только при
        applyToServer, потому что она меняет ровно две вещи - AllowedIPs
        и PresharedKey пира. Всё остальное (private_key, DNS,
        endpoint_allowed_ip, MTU, keepalive, раздельное туннелирование)
        существует только в конфиге, который получает клиент, и на сервере
        awg делать нечего.
        """
        if not self.configuration.getStatus():
            # Не игнорируем результат: если awg-quick up не удался, команда
            # "awg set" ниже тоже упадёт и пользователь увидит безликое
            # "Internal server error" вместо реальной причины
            startStatus, startMsg = self.configuration.toggleConfiguration()
            if not startStatus:
                current_app.logger.error(
                    f"{self.configuration.Name} could not be started while adding peer: {startMsg}")
                return False, f"Could not start interface: {startMsg}"

        # Before we do any compute, let us check if the given endpoint allowed ip is valid at all
        if not CheckAddress(endpoint_allowed_ip):
            return False, f"Endpoint Allowed IPs format is incorrect"

        peers = []
        for peer in self.configuration.getPeersList():
            # Make sure to exclude your own data when updating since its not really relevant
            if peer.id == self.id:
                continue
            peers.append(peer)

        used_allowed_ips = []
        for peer in peers:
            ips = peer.allowed_ip.split(',')
            ips = [ip.strip() for ip in ips]
            used_allowed_ips.append(ips)

        if allowed_ip in used_allowed_ips:
            return False, "Allowed IP already taken by another peer"

        if not ValidateDNSAddress(dns_addresses):
            return False, f"DNS IP-Address or FQDN is incorrect"

        splitValid, splitMsg = ValidateSplitTunnelList(split_tunnel_ips)
        if not splitValid:
            return False, splitMsg

        if split_tunnel_mode not in ("include", "exclude"):
            return False, "Split tunnel mode must be 'include' or 'exclude'"

        if isinstance(mtu, str):
            mtu = 0

        if isinstance(keepalive, str):
            keepalive = 0

        if mtu not in range(0, 1461):
            return False, "MTU format is not correct"

        if keepalive < 0:
            return False, "Persistent Keepalive format is not correct"

        if len(private_key) > 0:
            pubKey = GenerateWireguardPublicKey(private_key)
            if not pubKey[0] or pubKey[1] != self.id:
                return False, "Private key does not match with the public key"

        if not applyToServer:
            # Проверки выше уже прошли, менять на сервере нечего
            return True, None

        try:
            rand = random.Random()
            uid = str(uuid.UUID(int=rand.getrandbits(128), version=4))
            psk_exist = len(preshared_key) > 0

            if psk_exist:
                with open(uid, "w+") as f:
                    f.write(preshared_key)

            newAllowedIPs = allowed_ip.replace(" ", "")
            if not CheckAddress(newAllowedIPs):
                    return False, "Allowed IPs entry format is incorrect"

            command = [self.configuration.Protocol, "set", self.configuration.Name, "peer", self.id, "allowed-ips", newAllowedIPs, "preshared-key", uid if psk_exist else "/dev/null"]
            updateAllowedIp = subprocess.check_output(command, stderr=subprocess.STDOUT)

            if psk_exist: os.remove(uid)

            if len(updateAllowedIp.decode().strip("\n")) != 0:
                current_app.logger.error("Update peer failed when updating Allowed IPs")
                return False, "Internal server error"

            command = [f"{self.configuration.Protocol}-quick", "save", self.configuration.Name]
            saveConfig = subprocess.check_output(command, stderr=subprocess.STDOUT)

            if f"{self.configuration.Protocol} showconf {self.configuration.Name}" not in saveConfig.decode().strip('\n'):
                # Уточнение: awg-quick save печатает "awg showconf <имя>"
                current_app.logger.error("Update peer failed when saving the configuration")
                return False, "Internal server error"
            return True, None
        except subprocess.CalledProcessError as exc:
            current_app.logger.error(f"Subprocess call failed:\n{exc.output.decode('UTF-8')}")
            return False, "Internal server error"

    def __buildFileName(self) -> str:
        """
        Имя файла для выгрузки конфигурации пира.

        Раньше разрешался только ASCII ([a-zA-Z0-9_=+.-]), поэтому любое
        имя целиком на русском давало пустую строку, и файл сохранялся под
        именем, которое подставлял браузер. Теперь берутся буквы и цифры
        любого алфавита (str.isalnum() в Python 3 учитывает Unicode), плюс
        безопасный набор знаков.

        Остальные символы отбрасываются, поэтому имя нельзя превратить
        в путь: оба разделителя уходят вместе с управляющими символами.
        """
        source = (self.name or "").strip()
        if len(source) == 0:
            source = "UntitledPeer"

        # Пробелы не удаляем, а заменяем: так "Бадян Комп" не превратится
        # в "БадянКомп" и имя останется читаемым. В некоторых системах
        # пробелы в имени файла недопустимы.
        source = re.sub(r"\s+", "_", source)

        # Зарезервированные имена Windows: CON, PRN, AUX, NUL, COM1..9,
        # LPT1..9. Проверяется до очистки, как и раньше.
        if re.match(r"^(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(\..*)?$",
                    source, re.IGNORECASE):
            source = f"file_{source}"

        safe = "_-+.="
        result = "".join(
            ch for ch in source
            if ch.isalnum() or ch in safe
        ).strip(". ")

        if len(result) == 0:
            # Имя состояло только из символов, которые нельзя оставить.
            # Публичный ключ уникален, но его base64-алфавит содержит "/",
            # поэтому через тот же фильтр: иначе в имени появился бы
            # разделитель пути.
            result = "".join(
                ch for ch in (self.id or "")
                if ch.isalnum() or ch in safe
            ).strip(". ")
        if len(result) == 0:
            result = "peer"
        return result

    def downloadPeer(self) -> dict[str, str]:
        final = {
            "fileName": "",
            "file": ""
        }
        final["fileName"] = self.__buildFileName()

        interfaceSection = {
            "PrivateKey": self.private_key,
            "Address": self.allowed_ip,
            "MTU": (
                self.configuration.configurationInfo.OverridePeerSettings.MTU
                    if self.configuration.configurationInfo.OverridePeerSettings.MTU else self.mtu
            ),
            "DNS": (
                self.configuration.configurationInfo.OverridePeerSettings.DNS 
                    if self.configuration.configurationInfo.OverridePeerSettings.DNS else self.DNS
            )
        }

        if self.configuration.Protocol == "awg":
            interfaceSection.update({
                # AmneziaWG 2.0+ parameters
                "Jc": self.configuration.Jc,
                "Jmin": self.configuration.Jmin,
                "Jmax": self.configuration.Jmax,
                "S1": self.configuration.S1,
                "S2": self.configuration.S2,
                "S3": self.configuration.S3,
                "S4": self.configuration.S4,
                "H1": self.configuration.H1,
                "H2": self.configuration.H2,
                "H3": self.configuration.H3,
                "H4": self.configuration.H4,
                "I1": self.configuration.I1,
                "I2": self.configuration.I2,
                "I3": self.configuration.I3,
                "I4": self.configuration.I4,
                "I5": self.configuration.I5,
                # AmneziaWG 3.1 new parameters
                "HeaderProtectionKey": self.configuration.HeaderProtectionKey,
                "ContentPaddingAddition": self.configuration.ContentPaddingAddition,
                "RekeyAfterTime": self.configuration.RekeyAfterTime,
                "RekeyTimeout": self.configuration.RekeyTimeout,
                "RejectAfterTime": self.configuration.RejectAfterTime,
                "KeepaliveTimeout": self.configuration.KeepaliveTimeout,
                "MaxHandshakeAttempts": self.configuration.MaxHandshakeAttempts,
                "RandomTrailers": self.configuration.RandomTrailers,
                "DisableCookies": self.configuration.DisableCookies
            })

        peerSection = {
            "PublicKey": self.configuration.PublicKey,
            "AllowedIPs": (
                self.configuration.configurationInfo.OverridePeerSettings.EndpointAllowedIPs
                    if self.configuration.configurationInfo.OverridePeerSettings.EndpointAllowedIPs else self.endpoint_allowed_ip
            ),
            "Endpoint": f'{(self.configuration.configurationInfo.OverridePeerSettings.PeerRemoteEndpoint if self.configuration.configurationInfo.OverridePeerSettings.PeerRemoteEndpoint else self.configuration.DashboardConfig.GetConfig("Peers", "remote_endpoint")[1])}:{(self.configuration.configurationInfo.OverridePeerSettings.ListenPort if self.configuration.configurationInfo.OverridePeerSettings.ListenPort else self.configuration.ListenPort)}',
            "PersistentKeepalive": (
                self.configuration.configurationInfo.OverridePeerSettings.PersistentKeepalive 
                if self.configuration.configurationInfo.OverridePeerSettings.PersistentKeepalive
                else self.keepalive
            ),
            "PresharedKey": self.preshared_key
        }
        combine = [interfaceSection.items(), peerSection.items()]
        for s in range(len(combine)):
            if s == 0:
                final["file"] += "[Interface]\n"
            else:
                final["file"] += "\n[Peer]\n"
            for (key, val) in combine[s]:
                if val is not None and ((type(val) is str and len(val) > 0) or (type(val) is int and val > 0)):
                    final["file"] += f"{key} = {val}\n"

        final["file"] = jinja2.Template(final["file"]).render(configuration=self.configuration)


        if self.configuration.Protocol == "awg":
            amneziaConfig = self.__buildAmneziaConfig(final["file"])
            final["amneziaVPN"] = json.dumps(amneziaConfig)
            final["amneziaQRPack"] = self.__buildAmneziaQRPack(amneziaConfig)
        return final

    def __buildAmneziaConfig(self, configText: str) -> dict:
        """
        Структура .vpn-конфига AmneziaVPN: контейнер amnezia-awg с
        last_config в виде JSON-строки. Приложение читает параметры
        (Jc/S1/H1..., ключи, порт, PSK) именно из этой строки, а не из
        текста конфига, поэтому класть туда "голый" .conf нельзя.
        Формат повторяет рабочую реализацию wg-easy (generateAmneziaVPNClientConfig).
        """
        config = self.configuration
        override = config.configurationInfo.OverridePeerSettings
        endpoint = (override.PeerRemoteEndpoint
                    if override.PeerRemoteEndpoint
                    else config.DashboardConfig.GetConfig("Peers", "remote_endpoint")[1])
        port = config.ListenPort

        awgParams = {}
        for key in ("Jc", "Jmin", "Jmax", "S1", "S2", "S3", "S4",
                    "H1", "H2", "H3", "H4",
                    "I1", "I2", "I3", "I4", "I5"):
            value = getattr(config, key, None)
            if value is None or (isinstance(value, str) and len(value.strip()) == 0):
                continue
            awgParams[key] = str(value)

        allowedIps = [i.strip() for i in (
            override.EndpointAllowedIPs if override.EndpointAllowedIPs
            else self.endpoint_allowed_ip).split(",") if i.strip()]
        dnsServers = [d.strip() for d in (self.DNS or "").split(",") if d.strip()]

        mtu = override.MTU if override.MTU else self.mtu
        keepalive = override.PersistentKeepalive if override.PersistentKeepalive else self.keepalive

        lastConfig = {
            **awgParams,
            "allowed_ips": allowedIps,
            "client_ip": self.allowed_ip,
            "client_priv_key": self.private_key,
            "config": configText,
            "hostName": endpoint,
            "port": int(port),
            "psk_key": self.preshared_key or "",
            "server_pub_key": config.PublicKey,
        }
        if mtu:
            lastConfig["mtu"] = str(mtu)
        if keepalive:
            lastConfig["persistent_keep_alive"] = str(keepalive)

        container = {
            "isThirdPartyConfig": True,
            "last_config": json.dumps(lastConfig, ensure_ascii=False),
            "port": str(port),
            "transport_proto": "udp",
        }
        if "S3" in awgParams and "S4" in awgParams:
            container["protocol_version"] = "2"

        return {
            "containers": [{
                "awg": container,
                "container": "amnezia-awg",
            }],
            "defaultContainer": "amnezia-awg",
            "description": self.name,
            "dns1": dnsServers[0] if len(dnsServers) > 0 else "",
            "dns2": dnsServers[1] if len(dnsServers) > 1 else "",
            "hostName": endpoint,
        }

    @staticmethod
    def __buildAmneziaQRPack(amneziaConfig: dict) -> str:
        """
        QR-пакет приложения AmneziaVPN:
        [0..3] magic 0x07C00100, [4..7] len(zlib)+4, [8..11] len(json),
        далее zlib-deflate JSON - всё в base64url. Другой формат
        (просто base64 JSON) приложение не принимает: "error 900".
        """
        plain = json.dumps(amneziaConfig, ensure_ascii=False).encode("utf-8")
        packed = zlib.compress(plain, 9)
        header = struct.pack(">III", 0x07C00100, len(packed) + 4, len(plain))
        return base64.urlsafe_b64encode(header + packed).decode()

    def downloadPeerConf(self) -> dict[str, str]:
        """Конфигурация пира в формате .conf (AmneziaWG / WireGuard)"""
        peer_config = self.downloadPeer()
        return {
            "fileName": f"{peer_config['fileName']}.conf",
            "file": peer_config['file']
        }

    def downloadPeerJSON(self) -> dict[str, str]:
        """Конфигурация пира в формате .json (импорт в AmneziaVPN)"""
        peer_config = self.downloadPeer()
        if self.configuration.Protocol == "awg":
            payload = json.dumps(
                json.loads(peer_config["amneziaVPN"]), indent=2, ensure_ascii=False)
        else:
            payload = json.dumps({
                "containers": [{
                    "wireguard": {
                        "isThirdPartyConfig": True,
                        "last_config": peer_config['file'],
                        "port": self.configuration.ListenPort,
                        "transport_proto": "udp"
                    },
                    "container": "amnezia-wg"
                }],
                "defaultContainer": "amnezia-wg",
                "description": self.name,
                "hostName": (
                    self.configuration.configurationInfo.OverridePeerSettings.PeerRemoteEndpoint
                        if self.configuration.configurationInfo.OverridePeerSettings.PeerRemoteEndpoint
                        else self.configuration.DashboardConfig.GetConfig("Peers", "remote_endpoint")[1])
            }, indent=2, ensure_ascii=False)
        return {
            "fileName": f"{peer_config['fileName']}.json",
            "file": payload
        }

    def downloadPeerIPList(self) -> dict[str, str]:
        """
        Список подсетей раздельного туннелирования в формате AmneziaVPN (ip-list.json).

        Формат: [{"hostname": "<CIDR>", "ip": ""}, ...]
        Импортируется в AmneziaVPN: Настройки -> Раздельное туннелирование -> "Адреса из списка без VPN".
        """
        entries = []
        for raw in re.split(r"[\s,]+", (self.split_tunnel_ips or "").strip()):
            raw = raw.strip()
            if len(raw) == 0:
                continue
            try:
                ipaddress.ip_network(raw, strict=False)
            except ValueError as e:
                # Список валидируется при сохранении пира, сюда может попасть
                # только запись, созданная до включения валидации
                current_app.logger.error(f"Peer {self.id} has an invalid split tunnel entry: {raw} ({e})")
                continue
            entries.append({"hostname": raw, "ip": ""})
        return {
            # Тот же санитайзер, что и для .conf: иначе русское имя
            # превратилось бы в "_ip-list.json"
            "fileName": f"{self.__buildFileName()}_ip-list.json",
            "file": json.dumps(entries, ensure_ascii=False)
        }

    def getJobs(self):
        self.jobs = self.configuration.AllPeerJobs.searchJob(self.configuration.Name, self.id)

    def getShareLink(self):
        self.ShareLink = self.configuration.AllPeerShareLinks.getLink(self.configuration.Name, self.id)

    def resetDataUsage(self, mode: str):
        try:
            with self.configuration.engine.begin() as conn:
                if mode == "total":
                    conn.execute(
                        self.configuration.peersTable.update().values({
                            "total_data": 0,
                            "cumu_data": 0,
                            "total_receive": 0,
                            "cumu_receive": 0,
                            "total_sent": 0,
                            "cumu_sent": 0
                        }).where(
                            self.configuration.peersTable.c.id == self.id
                        )
                    )
                    self.total_data = 0
                    self.total_receive = 0
                    self.total_sent = 0
                    self.cumu_data = 0
                    self.cumu_sent = 0
                    self.cumu_receive = 0
                elif mode == "receive":
                    conn.execute(
                        self.configuration.peersTable.update().values({
                            "total_receive": 0,
                            "cumu_receive": 0,
                        }).where(
                            self.configuration.peersTable.c.id == self.id
                        )
                    )
                    self.cumu_receive = 0
                    self.total_receive = 0
                elif mode == "sent":
                    conn.execute(
                        self.configuration.peersTable.update().values({
                            "total_sent": 0,
                            "cumu_sent": 0
                        }).where(
                            self.configuration.peersTable.c.id == self.id
                        )
                    )
                    self.cumu_sent = 0
                    self.total_sent = 0
                else:
                    return False
        except Exception as e:
            print(e)
            return False
        return True
    
    def getEndpoints(self):
        result = []
        with self.configuration.engine.connect() as conn:
            result = conn.execute(
                db.select(
                    self.configuration.peersHistoryEndpointTable.c.endpoint
                ).group_by(
                    self.configuration.peersHistoryEndpointTable.c.endpoint
                ).where(
                    self.configuration.peersHistoryEndpointTable.c.id == self.id
                )
            ).mappings().fetchall()
        return list(result)
    
    def getTraffics(self, interval: int = 30, startDate: datetime.datetime = None, endDate: datetime.datetime = None):
        if startDate is None and endDate is None:
            endDate = datetime.datetime.now()
            startDate = endDate - timedelta(minutes=interval)
        else:
            endDate = endDate.replace(hour=23, minute=59, second=59, microsecond=999999)
            startDate = startDate.replace(hour=0, minute=0, second=0, microsecond=0)

        with self.configuration.engine.connect() as conn:
            result = conn.execute(
                db.select(
                    self.configuration.peersTransferTable.c.cumu_data,
                    self.configuration.peersTransferTable.c.total_data,
                    self.configuration.peersTransferTable.c.cumu_receive,
                    self.configuration.peersTransferTable.c.total_receive,
                    self.configuration.peersTransferTable.c.cumu_sent,
                    self.configuration.peersTransferTable.c.total_sent,
                    self.configuration.peersTransferTable.c.time
                ).where(
                    db.and_(
                        self.configuration.peersTransferTable.c.id == self.id,
                        self.configuration.peersTransferTable.c.time <= endDate,
                        self.configuration.peersTransferTable.c.time >= startDate,
                        )
                ).order_by(
                    self.configuration.peersTransferTable.c.time
                )
            ).mappings().fetchall()
        return list(result)
            
    
    def getSessions(self, startDate: datetime.datetime = None, endDate: datetime.datetime = None):
        if endDate is None:
            endDate = datetime.datetime.now()
        
        if startDate is None:
            startDate = endDate

        endDate = endDate.replace(hour=23, minute=59, second=59, microsecond=999999)
        startDate = startDate.replace(hour=0, minute=0, second=0, microsecond=0)
            

        with self.configuration.engine.connect() as conn:
            result = conn.execute(
                db.select(
                    self.configuration.peersTransferTable.c.time
                ).where(
                    db.and_(
                        self.configuration.peersTransferTable.c.id == self.id,
                        self.configuration.peersTransferTable.c.time <= endDate,
                        self.configuration.peersTransferTable.c.time >= startDate,
                    )
                ).order_by(
                    self.configuration.peersTransferTable.c.time
                )
            ).fetchall()
        time = list(map(lambda x : x[0], result))
        return time
    
    def __duration(self, t1: datetime.datetime, t2: datetime.datetime):
        delta = t1 - t2
        
        hours, remainder = divmod(delta.total_seconds(), 3600)
        minutes, seconds = divmod(remainder, 60)
        return f"{int(hours):02}:{int(minutes):02}:{int(seconds):02}"

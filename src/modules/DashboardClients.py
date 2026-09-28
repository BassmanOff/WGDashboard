import datetime
import hashlib
import random
import uuid

import bcrypt
import pyotp
import sqlalchemy as db
import requests

from .DatabaseConnection import ConnectionString
from .DashboardClientsPeerAssignment import DashboardClientsPeerAssignment
from .DashboardClientsTOTP import DashboardClientsTOTP
from .DashboardOIDC import DashboardOIDC
from .Utilities import ValidatePasswordStrength
from .DashboardLogger import DashboardLogger
from flask import session


class DashboardClients:
    def __init__(self, wireguardConfigurations):
        self.logger = DashboardLogger()
        self.engine = db.create_engine(ConnectionString("wgdashboard"))
        self.metadata = db.MetaData()
        self.OIDC = DashboardOIDC("Client")
        
        self.dashboardClientsTable = db.Table(
            'DashboardClients', self.metadata,
            db.Column('ClientID', db.String(255), nullable=False, primary_key=True),
            db.Column('Email', db.String(255), nullable=False, index=True),
            db.Column('Password', db.String(500)),
            db.Column('TotpKey', db.String(500)),
            db.Column('TotpKeyVerified', db.Integer),
            db.Column('CreatedDate', 
                      (db.DATETIME if 'sqlite:///' in ConnectionString("wgdashboard") else db.TIMESTAMP),
                      server_default=db.func.now()),
            db.Column('DeletedDate', 
                      (db.DATETIME if 'sqlite:///' in ConnectionString("wgdashboard") else db.TIMESTAMP)),
            extend_existing=True,
        )
        
        self.dashboardOIDCClientsTable = db.Table(
            'DashboardOIDCClients', self.metadata,
            db.Column('ClientID', db.String(255), nullable=False, primary_key=True),
            db.Column('Email', db.String(255), nullable=False, index=True),
            db.Column('ProviderIssuer', db.String(500), nullable=False, index=True),
            db.Column('ProviderSubject', db.String(500), nullable=False, index=True),
            db.Column('CreatedDate',
                      (db.DATETIME if 'sqlite:///' in ConnectionString("wgdashboard") else db.TIMESTAMP),
                      server_default=db.func.now()),
            db.Column('DeletedDate',
                      (db.DATETIME if 'sqlite:///' in ConnectionString("wgdashboard") else db.TIMESTAMP)),
            extend_existing=True,
        )

        self.dashboardClientsInfoTable = db.Table(
            'DashboardClientsInfo', self.metadata,
            db.Column('ClientID', db.String(255), nullable=False, primary_key=True),
            db.Column('Name', db.String(500)),
            # --- Трекер оплат (используется администратором вручную) ---
            db.Column('Telegram', db.String(255)),
            db.Column('Comment', db.Text),
            db.Column('PaidUntil',
                      (db.DATETIME if 'sqlite:///' in ConnectionString("wgdashboard") else db.TIMESTAMP)),
            extend_existing=True,   
        )
        
        self.dashboardClientsPasswordResetLinkTable = db.Table(
            'DashboardClientsPasswordResetLinks', self.metadata,
            db.Column('ResetToken', db.String(255), nullable=False, primary_key=True),
            db.Column('ClientID', db.String(255), nullable=False),
            db.Column('CreatedDate',
                      (db.DATETIME if 'sqlite:///' in ConnectionString("wgdashboard") else db.TIMESTAMP),
                      server_default=db.func.now()),
            db.Column('ExpiryDate',
                      (db.DATETIME if 'sqlite:///' in ConnectionString("wgdashboard") else db.TIMESTAMP)),
            extend_existing=True
        )

        self.metadata.create_all(self.engine)
        self.__migrateClientsInfoTable()
        self.Clients = {}
        self.ClientsRaw = []
        self.__getClients()
        self.DashboardClientsTOTP = DashboardClientsTOTP()
        self.DashboardClientsPeerAssignment = DashboardClientsPeerAssignment(wireguardConfigurations)
        
    def __migrateClientsInfoTable(self):
        """
        create_all() не добавляет колонки в уже существующие таблицы,
        поэтому недостающие колонки добавляем через ALTER TABLE.
        """
        expected = {
            'Telegram': db.String(255),
            'Comment': db.Text,
            'PaidUntil': (db.DATETIME if 'sqlite:///' in ConnectionString("wgdashboard") else db.TIMESTAMP),
        }
        try:
            inspector = db.inspect(self.engine)
            if not inspector.has_table('DashboardClientsInfo'):
                return
            existing = [c['name'] for c in inspector.get_columns('DashboardClientsInfo')]
            with self.engine.begin() as conn:
                preparer = self.engine.dialect.identifier_preparer
                for col_name, col_type in expected.items():
                    if col_name in existing:
                        continue
                    type_str = col_type().compile(dialect=self.engine.dialect)
                    conn.execute(db.text(
                        f"ALTER TABLE {preparer.quote_identifier('DashboardClientsInfo')} "
                        f"ADD COLUMN {preparer.quote_identifier(col_name)} {type_str}"
                    ))
                    self.logger.log(Message=f"Clients table migration: added column '{col_name}'")
        except Exception as e:
            self.logger.log(Status="false", Message=f"Clients table migration failed: {e}")

    def __getClients(self):
        with self.engine.connect() as conn:
            localClients = db.select(
                self.dashboardClientsTable.c.ClientID,
                self.dashboardClientsTable.c.Email,
                db.literal_column("'Local'").label("ClientGroup")
            ).where(
                self.dashboardClientsTable.c.DeletedDate.is_(None)
            )
            
            oidcClients = db.select(
                self.dashboardOIDCClientsTable.c.ClientID,
                self.dashboardOIDCClientsTable.c.Email,
                self.dashboardOIDCClientsTable.c.ProviderIssuer.label("ClientGroup"),
            ).where(
                self.dashboardOIDCClientsTable.c.DeletedDate.is_(None)
            )
            
            union = db.union(localClients, oidcClients).alias("U")
            
            self.ClientsRaw = [dict(x) for x in conn.execute(
                db.select(
                    union, 
                    self.dashboardClientsInfoTable.c.Name,
                    self.dashboardClientsInfoTable.c.Telegram,
                    self.dashboardClientsInfoTable.c.Comment,
                    self.dashboardClientsInfoTable.c.PaidUntil
                ).outerjoin(self.dashboardClientsInfoTable, 
                            union.c.ClientID == self.dashboardClientsInfoTable.c.ClientID)
            ).mappings().fetchall()]
            self.__annotatePaymentStatus()
            
            groups = set(map(lambda c: c.get('ClientGroup'), self.ClientsRaw))
            gr = {}
            for g in groups:
                gr[(g if g == 'Local' else self.OIDC.GetProviderNameByIssuer(g))] = [
                    dict(x) for x in list(
                        filter(lambda c: c.get('ClientGroup') == g, self.ClientsRaw)
                    )
                ]
            self.Clients = gr
            
    def __annotatePaymentStatus(self):
        """
        Добавляет к каждому клиенту вычисленные поля:
          PaymentStatus: 'unset' | 'active' | 'expiring' | 'expired'
          DaysRemaining: целое число дней до PaidUntil (None, если срок не задан)
        """
        today = datetime.datetime.now().replace(hour=0, minute=0, second=0, microsecond=0)
        for c in self.ClientsRaw:
            paidUntil = c.get('PaidUntil')
            if paidUntil is None:
                c['PaymentStatus'] = 'unset'
                c['DaysRemaining'] = None
                c['PaidUntilFormatted'] = None
                continue
            if isinstance(paidUntil, str):
                try:
                    paidUntil = datetime.datetime.strptime(paidUntil[:19], "%Y-%m-%d %H:%M:%S")
                except ValueError:
                    paidUntil = None
            if paidUntil is None:
                c['PaymentStatus'] = 'unset'
                c['DaysRemaining'] = None
                c['PaidUntilFormatted'] = None
                continue
            # Срок считается истёкшим в конце указанного дня
            days = (paidUntil.date() - today.date()).days
            c['DaysRemaining'] = days
            c['PaidUntilFormatted'] = paidUntil.strftime("%Y-%m-%d")
            if days < 0:
                c['PaymentStatus'] = 'expired'
            elif days <= 7:
                c['PaymentStatus'] = 'expiring'
            else:
                c['PaymentStatus'] = 'active'

    def GetAllClients(self):
        self.__getClients()
        return self.Clients
    
    def GetAllClientsRaw(self):
        self.__getClients()
        return self.ClientsRaw
    
    def GetClient(self, ClientID) -> dict[str, str] | None:
        c = filter(lambda x: x['ClientID'] == ClientID, self.ClientsRaw)
        client = next((dict(client) for client in c), None)
        if client is not None:
            client['ClientGroup'] = self.OIDC.GetProviderNameByIssuer(client['ClientGroup'])
        return client
    
    def GetClientProfile(self, ClientID):
        """
        Возвращает профиль клиента для клиентского интерфейса.
        ВАЖНО: служебные поля администратора (Telegram, Comment, PaidUntil)
        намеренно не возвращаются — они видны только администратору.
        """
        with self.engine.connect() as conn:
            row = conn.execute(
                db.select(self.dashboardClientsInfoTable.c.Name).where(
                    self.dashboardClientsInfoTable.c.ClientID == ClientID
                )
            ).mappings().fetchone()
            return dict(row) if row is not None else {}
    
    def SignIn_ValidatePassword(self, Email, Password) -> bool:
        if not all([Email, Password]):
            return False
        existingClient = self.SignIn_UserExistence(Email)
        if existingClient:
            return bcrypt.checkpw(Password.encode("utf-8"), existingClient.get("Password").encode("utf-8"))            
        return False
        
    def SignIn_UserExistence(self, Email):
        with self.engine.connect() as conn:
            existingClient = conn.execute(
                self.dashboardClientsTable.select().where(
                    self.dashboardClientsTable.c.Email == Email
                )
            ).mappings().fetchone()
            return existingClient
    
    def SignIn_OIDC_UserExistence(self, data: dict[str, str]):
        with self.engine.connect() as conn:
            existingClient = conn.execute(
                self.dashboardOIDCClientsTable.select().where(
                    db.and_(
                        self.dashboardOIDCClientsTable.c.ProviderIssuer == data.get('iss'),
                        self.dashboardOIDCClientsTable.c.ProviderSubject == data.get('sub'),
                    )
                )
            ).mappings().fetchone()
            return existingClient
        
    def SignUp_OIDC(self, data: dict[str, str]) -> tuple[bool, str] | tuple[bool, None]:
        if not self.SignIn_OIDC_UserExistence(data):
            with self.engine.begin() as conn:
                newClientUUID = str(uuid.uuid4())
                conn.execute(
                    self.dashboardOIDCClientsTable.insert().values({
                        "ClientID": newClientUUID,
                        "Email": data.get('email', ''),
                        "ProviderIssuer": data.get('iss', ''),
                        "ProviderSubject": data.get('sub', '')
                    })
                )
                conn.execute(
                    self.dashboardClientsInfoTable.insert().values({
                        "ClientID": newClientUUID,
                        "Name": data.get("name")
                    })
                )
                self.logger.log(Message=f"User {data.get('email', '')} from {data.get('iss', '')} signed up")
            self.__getClients()
            return True, newClientUUID
        return False, "User already signed up"
    
    def SignOut_OIDC(self):
        sessionPayload = session.get('OIDCPayload')
        status, oidc_config = self.OIDC.GetProviderConfiguration(session.get('SignInPayload').get("Provider"))        
        signOut = requests.get(
            oidc_config.get("end_session_endpoint"), 
            params={
                'id_token_hint': session.get('SignInPayload').get("Payload").get('sid')
            }
        )
        return True
        
    def SignIn_OIDC(self, **kwargs):
        status, data = self.OIDC.VerifyToken(**kwargs)
        if not status:
            return False, "Sign in failed. Reason: " + data
        existingClient = self.SignIn_OIDC_UserExistence(data)
        if not existingClient:
            status, newClientUUID = self.SignUp_OIDC(data)
            session['ClientID'] = newClientUUID
        else:
            session['ClientID'] = existingClient.get("ClientID")
        session['SignInMethod'] = 'OIDC'
        session['SignInPayload'] = {
            "Provider": kwargs.get('provider'),
            "Payload": data
        }
        return True, data
        
    def SignIn(self, Email, Password) -> tuple[bool, str]:
        if not all([Email, Password]):
            return False, "Please fill in all fields"
        existingClient = self.SignIn_UserExistence(Email)
        if existingClient:
            checkPwd = self.SignIn_ValidatePassword(Email, Password)
            if checkPwd:
                session['SignInMethod'] = 'local'
                session['Email'] = Email
                session['ClientID'] = existingClient.get("ClientID")
                return True, self.DashboardClientsTOTP.GenerateToken(existingClient.get("ClientID"))
        return False, "Email or Password is incorrect"
    
    def SignIn_GetTotp(self, Token: str, UserProvidedTotp: str = None) -> tuple[bool, str] or tuple[bool, None, str]:
        status, data = self.DashboardClientsTOTP.GetTotp(Token)
        
        if not status:
            return False, "TOTP Token is invalid"    
        if UserProvidedTotp is None:
            if data.get('TotpKeyVerified') is None:
                return True, pyotp.totp.TOTP(data.get('TotpKey')).provisioning_uri(name=data.get('Email'),
                                                                                   issuer_name="WGDashboard Client")
        else:
            totpMatched = pyotp.totp.TOTP(data.get('TotpKey')).verify(UserProvidedTotp)
            if not totpMatched:
                return False, "TOTP is does not match"
            else:
                self.DashboardClientsTOTP.RevokeToken(Token)
        if data.get('TotpKeyVerified') is None:
            with self.engine.begin() as conn:
                conn.execute(
                    self.dashboardClientsTable.update().values({
                        'TotpKeyVerified': 1
                    }).where(
                        self.dashboardClientsTable.c.ClientID == data.get('ClientID')
                    )
                )
              
        return True, None
        
    def SignUp(self, Email, Password, ConfirmPassword) -> tuple[bool, str] or tuple[bool, None]:
        try:
            if not all([Email, Password, ConfirmPassword]):
                return False, "Please fill in all fields"
            if Password != ConfirmPassword:
                return False, "Passwords does not match"

            existingClient = self.SignIn_UserExistence(Email)
            if existingClient:
                return False, "Email already signed up"
    
            pwStrength, msg = ValidatePasswordStrength(Password)
            if not pwStrength:
                return pwStrength, msg
    
            with self.engine.begin() as conn:
                newClientUUID = str(uuid.uuid4())
                totpKey = pyotp.random_base32()
                encodePassword = Password.encode('utf-8')
                conn.execute(
                    self.dashboardClientsTable.insert().values({
                        "ClientID": newClientUUID,
                        "Email": Email,
                        "Password": bcrypt.hashpw(encodePassword, bcrypt.gensalt()).decode("utf-8"),
                        "TotpKey": totpKey
                    })
                )
                conn.execute(
                    self.dashboardClientsInfoTable.insert().values({
                        "ClientID": newClientUUID
                    })
                )
                self.logger.log(Message=f"User {Email} signed up")
            self.__getClients()
        except Exception as e:
            self.logger.log(Status="false", Message=f"Signed up failed, reason: {str(e)}")
            return False, "Signe up failed."
            
        return True, None
    
    def GetClientAssignedPeers(self, ClientID):
        return self.DashboardClientsPeerAssignment.GetAssignedPeers(ClientID)
    
    def ResetClientPassword(self, ClientID, NewPassword, ConfirmNewPassword) -> tuple[bool, str] | tuple[bool, None]:
        c = self.GetClient(ClientID)
        if c is None:
            return False, "Client does not exist"
        
        if NewPassword != ConfirmNewPassword:
            return False, "New passwords does not match"

        pwStrength, msg = ValidatePasswordStrength(NewPassword)
        if not pwStrength:
            return pwStrength, msg
        try:
            with self.engine.begin() as conn:
                conn.execute(
                    self.dashboardClientsTable.update().values({
                        "TotpKeyVerified": None,
                        "TotpKey": pyotp.random_base32(),
                        "Password": bcrypt.hashpw(NewPassword.encode('utf-8'), bcrypt.gensalt()).decode("utf-8"),
                    }).where(
                        self.dashboardClientsTable.c.ClientID == ClientID
                    )
                )
                self.logger.log(Message=f"User {ClientID} reset password and TOTP")
        except Exception as e:
            self.logger.log(Status="false", Message=f"User {ClientID} reset password failed, reason: {str(e)}")
            return False, "Reset password failed."
        
        
        return True, None
            
    def UpdateClientPassword(self, ClientID, CurrentPassword, NewPassword, ConfirmNewPassword) -> tuple[bool, str] | tuple[bool, None]:
        c = self.GetClient(ClientID)
        if c is None:
            return False, "Client does not exist"
        
        if not all([CurrentPassword, NewPassword, ConfirmNewPassword]):
            return False, "Please fill in all fields"
        
        if not self.SignIn_ValidatePassword(c.get('Email'), CurrentPassword):
            return False, "Current password does not match"
        
        if NewPassword != ConfirmNewPassword:
            return False, "New passwords does not match"

        pwStrength, msg = ValidatePasswordStrength(NewPassword)
        if not pwStrength:
            return pwStrength, msg
        try:
            with self.engine.begin() as conn:
                conn.execute(
                    self.dashboardClientsTable.update().values({
                        "Password": bcrypt.hashpw(NewPassword.encode('utf-8'), bcrypt.gensalt()).decode("utf-8"),
                    }).where(
                        self.dashboardClientsTable.c.ClientID == ClientID
                    )
                )
                self.logger.log(Message=f"User {ClientID} updated password")
        except Exception as e:
            self.logger.log(Status="false", Message=f"User {ClientID} update password failed, reason: {str(e)}")
            return False, "Update password failed."
        return True, None
    
    def UpdateClientProfile(self, ClientID, Name):
        try:
            with self.engine.begin() as conn:
                conn.execute(
                    self.dashboardClientsInfoTable.update().values({
                        "Name": Name
                    }).where(
                        self.dashboardClientsInfoTable.c.ClientID == ClientID
                    )
                )
            self.logger.log(Message=f"User {ClientID} updated name to {Name}")
        except Exception as e:
            self.logger.log(Status="false", Message=f"User {ClientID} updated name to {Name} failed")
            return False
        return True

    def UpdateClientPaymentInfo(self, ClientID, Telegram=None, Comment=None, PaidUntil=None) -> tuple[bool, str | None]:
        """
        Обновляет контактные данные и срок оплаты клиента.
        None означает "не менять", пустая строка — "очистить".
        """
        if self.GetClient(ClientID) is None:
            return False, "Client does not exist"

        values = {}
        if Telegram is not None:
            values["Telegram"] = Telegram.strip()
        if Comment is not None:
            values["Comment"] = Comment
        if PaidUntil is not None:
            if PaidUntil == "":
                values["PaidUntil"] = None
            else:
                try:
                    values["PaidUntil"] = datetime.datetime.strptime(
                        PaidUntil, "%Y-%m-%d"
                    ).replace(hour=23, minute=59, second=59, microsecond=0)
                except ValueError:
                    return False, "PaidUntil must be in YYYY-MM-DD format"

        if len(values) == 0:
            return False, "Nothing to update"

        try:
            with self.engine.begin() as conn:
                updated = conn.execute(
                    self.dashboardClientsInfoTable.update().values(values).where(
                        self.dashboardClientsInfoTable.c.ClientID == ClientID
                    )
                ).rowcount
                if updated == 0:
                    # Записи об информации может не быть (например, клиент из старой версии)
                    base = {"ClientID": ClientID}
                    base.update({k: v for k, v in values.items() if k != 'Name'})
                    conn.execute(
                        self.dashboardClientsInfoTable.insert().values(base)
                    )
            self.logger.log(
                Message=f"User {ClientID} payment info updated: {', '.join(values.keys())}")
        except Exception as e:
            self.logger.log(Status="false",
                            Message=f"User {ClientID} payment info update failed, reason: {e}")
            return False, "Update failed"

        self.__getClients()
        return True, None

    def ExtendClientPayment(self, ClientID, Days: int) -> tuple[bool, str | None]:
        """Продлевает срок оплаты на N дней от текущего (или от сегодня, если срок истёк)."""
        if self.GetClient(ClientID) is None:
            return False, "Client does not exist"
        if type(Days) is not int or Days <= 0 or Days > 3650:
            return False, "Days must be an integer between 1 and 3650"

        today = datetime.datetime.now().replace(hour=0, minute=0, second=0, microsecond=0)
        current = None
        with self.engine.connect() as conn:
            row = conn.execute(
                db.select(self.dashboardClientsInfoTable.c.PaidUntil).where(
                    self.dashboardClientsInfoTable.c.ClientID == ClientID
                )
            ).mappings().fetchone()
            if row is not None:
                current = row.get('PaidUntil')
        if isinstance(current, str):
            try:
                current = datetime.datetime.strptime(current[:19], "%Y-%m-%d %H:%M:%S")
            except ValueError:
                current = None

        # Если срок ещё не истёк, продлеваем от него, иначе — от сегодня
        base = current if (current is not None and current.date() >= today.date()) else today
        newDate = (base + datetime.timedelta(days=Days)).replace(
            hour=23, minute=59, second=59, microsecond=0)

        return self.UpdateClientPaymentInfo(
            ClientID, PaidUntil=newDate.strftime("%Y-%m-%d"))

    def GetOverdueClients(self) -> list:
        """Клиенты с истёкшим сроком оплаты (для сводки/уведомлений)."""
        self.__getClients()
        return list(filter(lambda c: c.get('PaymentStatus') == 'expired',
                           self.ClientsRaw))
    
    def DeleteClient(self, ClientID):
        try:
            with self.engine.begin() as conn:
                client = self.GetClient(ClientID)
                if client.get("ClientGroup") == "Local":
                    conn.execute(
                        self.dashboardClientsTable.delete().where(
                            self.dashboardClientsTable.c.ClientID == ClientID
                        )
                    )
                else:
                    conn.execute(
                        self.dashboardOIDCClientsTable.delete().where(
                            self.dashboardOIDCClientsTable.c.ClientID == ClientID
                        )
                    )
                conn.execute(
                    self.dashboardClientsInfoTable.delete().where(
                        self.dashboardClientsInfoTable.c.ClientID == ClientID
                    )
                )
            self.DashboardClientsPeerAssignment.UnassignPeers(ClientID)
            self.__getClients()
        except Exception as e:
            self.logger.log(Status="false", Message=f"Failed to delete {ClientID}")
            return False
        return True
    
    '''
    For WGDashboard Admin to Manage Clients
    '''

    def GenerateClientPasswordResetToken(self, ClientID) -> bool | str:
        c = self.GetClient(ClientID)
        if c is None:
            return False
        
        newToken = str(random.randint(0, 999999)).zfill(6)
        with self.engine.begin() as conn:
            conn.execute(
                self.dashboardClientsPasswordResetLinkTable.update().values({
                    "ExpiryDate": datetime.datetime.now()
                
                }).where(
                    db.and_(
                        self.dashboardClientsPasswordResetLinkTable.c.ClientID == ClientID,
                        self.dashboardClientsPasswordResetLinkTable.c.ExpiryDate > db.func.now()
                    )
                )
            )
            conn.execute(
                self.dashboardClientsPasswordResetLinkTable.insert().values({
                    "ResetToken": newToken,
                    "ClientID": ClientID,
                    "CreatedDate": datetime.datetime.now(),
                    "ExpiryDate": datetime.datetime.now() + datetime.timedelta(minutes=30)
                })
            )
        
        return newToken
        
    def ValidateClientPasswordResetToken(self, ClientID, Token):
        c = self.GetClient(ClientID)
        if c is None:
            return False
        with self.engine.connect() as conn:
            t = conn.execute(
                self.dashboardClientsPasswordResetLinkTable.select().where(
                    db.and_(self.dashboardClientsPasswordResetLinkTable.c.ClientID == ClientID,
                            self.dashboardClientsPasswordResetLinkTable.c.ResetToken == Token,
                            self.dashboardClientsPasswordResetLinkTable.c.ExpiryDate > datetime.datetime.now())
                    
                )
            ).mappings().fetchone()
        return t is not None
    
    def RevokeClientPasswordResetToken(self, ClientID, Token):
        with self.engine.begin() as conn:
            conn.execute(
                self.dashboardClientsPasswordResetLinkTable.update().values({
                    "ExpiryDate": datetime.datetime.now()
                }).where(
                    db.and_(self.dashboardClientsPasswordResetLinkTable.c.ClientID == ClientID,
                            self.dashboardClientsPasswordResetLinkTable.c.ResetToken == Token)
                )
            )
        return True
    
    def GetAssignedPeerClients(self, ConfigurationName, PeerID):
        c = self.DashboardClientsPeerAssignment.GetAssignedClients(ConfigurationName, PeerID)
        for a in c:
            client = self.GetClient(a.ClientID)
            if client is not None:
                a.Client = self.GetClient(a.ClientID)
        return c
    
    def GetClientAssignedPeersGrouped(self, ClientID):
        client = self.GetClient(ClientID)
        if client is not None:
            p = self.DashboardClientsPeerAssignment.GetAssignedPeers(ClientID)
            configs = set(map(lambda x : x['configuration_name'], p))
            d = {}
            for i in configs:
                d[i] = list(filter(lambda x : x['configuration_name'] == i, p)) 
            return d
        return None

    def AssignClient(self, ConfigurationName, PeerID, ClientID) -> tuple[bool, dict[str, str]] | tuple[bool, None]:
        return self.DashboardClientsPeerAssignment.AssignClient(ClientID, ConfigurationName, PeerID) 
    
    def UnassignClient(self, AssignmentID):
        return self.DashboardClientsPeerAssignment.UnassignClients(AssignmentID)
        
"""
Регрессионные тесты валидации параметров AmneziaWG 3.1.

Проверяется:
1. Единая серверная валидация ValidateAmneziaWGSettings(): типы/диапазоны
   (uint16, range<uint16>, range<uint32>), форматы CPS (I1-I5),
   HeaderProtectionKey, on/off — согласно docs.amnezia.org
   (документация AmneziaWG 3.1);
2. Взаимные ограничения: Jmax >= Jmin, непересечение H1-H4
   (совместимые значения H1..H4 = 1..4 исключены),
   HeaderProtectionKey требует S1-S4 >= 12;
3. Пути обхода через API правки существующей конфигурации:
   updateWireguardConfiguration -> updateConfigurationSettings() и
   updateWireguardConfigurationRawFile -> updateRawConfigurationFile()
   обязаны прогнать изменения через ту же валидацию и не сохранять
   частично (файл не переписывается при невалидных данных);
4. Штатные конфигурации не отвергаются (production-пресет Jc=5,
   S1-S4=21, H1-H4=1..4 + HeaderProtectionKey проходит).

Запуск из src/:  python -m unittest discover -s tests -v
"""
import sys
import tempfile
import unittest
from pathlib import Path

SRC = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SRC))

import re

from modules.AmneziaValidation import (
    ValidateAmneziaWGSettings, ValidateAmneziaWG31Params,
    ValidateH1H4NonOverlapping)
from modules.WireguardConfiguration import WireguardConfiguration

# Production-пресет проекта (hardened, согласован с клиентскими конфигами):
# Jc=5, Jmin/Jmax=40/60, S1-S4=21, H1-H4=1..4 (compat), HeaderProtectionKey
VALID_HPK = "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY="  # 32 байта base64

PRODUCTION_PRESET = {
    "Jc": "5", "Jmin": "40", "Jmax": "60",
    "S1": "21", "S2": "21", "S3": "21", "S4": "21",
    "H1": "1", "H2": "2", "H3": "3", "H4": "4",
    "HeaderProtectionKey": VALID_HPK,
    "I1": "<b 0xf6ab3267fa><b 0xf6ab><t><r 10>",
}

CONF_TEMPLATE = """[Interface]
PrivateKey = AA=
Address = 10.9.9.0/24
ListenPort = 443
Jc = 5
Jmin = 40
Jmax = 60
S1 = 21
S2 = 21
S3 = 21
S4 = 21
H1 = 1
H2 = 2
H3 = 3
H4 = 4
HeaderProtectionKey = {hpk}

[Peer]
#Name# = TestClient
PublicKey = BB=
AllowedIPs = 10.9.9.2/32
"""


def parseInterfaceAttrs(confText: str) -> dict:
    """Упрощённый __parseConfigurationFile(): [Interface]-ключи в атрибуты."""
    attrs = {}
    inInterface = False
    for line in confText.splitlines():
        stripped = line.strip()
        if stripped.startswith("[") and stripped.endswith("]"):
            inInterface = stripped == "[Interface]"
            continue
        if inInterface and len(stripped) > 0:
            split = re.split(r'\s*=\s*', stripped, maxsplit=1)
            if len(split) == 2:
                attrs[split[0]] = split[1].strip()
    return attrs


def makeInstance(confText: str, protocol: str = "awg", tmp=None):
    """Инстанс конфигурации без __init__ (БД/ini не затрагиваются);
    атрибуты согласованы с .conf; toggle/backup замоканы."""
    tmp = tmp or tempfile.TemporaryDirectory()
    path = Path(tmp.name) / f"{protocol.upper()}.conf"
    path.write_text(confText, encoding="utf-8")

    inst = WireguardConfiguration.__new__(WireguardConfiguration)
    inst.Protocol = protocol
    inst.Name = "AWG"
    inst.Status = False
    inst.configPath = str(path)
    for key, value in parseInterfaceAttrs(confText).items():
        setattr(inst, key, value)
    # отсутствующие в conf amnezia-поля — дефолты класса AmneziaConfiguration
    for key in ("Jc", "Jmin", "Jmax", "S1", "S2", "S3", "S4"):
        setattr(inst, key, getattr(inst, key, "0"))
    for key in ("H1", "H2", "H3", "H4"):
        setattr(inst, key, getattr(inst, key, "0"))
    for key in ("I1", "I2", "I3", "I4", "I5"):
        setattr(inst, key, getattr(inst, key, "0"))
    for key in ("HeaderProtectionKey", "ContentPaddingAddition",
                "RekeyAfterTime", "RekeyTimeout", "RejectAfterTime",
                "KeepaliveTimeout", "MaxHandshakeAttempts"):
        setattr(inst, key, getattr(inst, key, ""))
    inst.RandomTrailers = "off"
    inst.DisableCookies = "off"

    calls = {"backup": 0, "toggle": 0}
    inst.backupConfigurationFile = lambda: (
        calls.__setitem__("backup", calls["backup"] + 1),
        (True, {"filename": "b.conf", "backupDate": ""}))[1]
    inst.toggleConfiguration = lambda: (
        calls.__setitem__("toggle", calls["toggle"] + 1), (True, None))[1]
    return inst, tmp, calls, path


class AmneziaValidationSettings(unittest.TestCase):
    """Единая валидация: типы, диапазоны, взаимные ограничения."""

    def test_production_preset_accepted(self):
        self.assertEqual(ValidateAmneziaWGSettings(PRODUCTION_PRESET), (True, ""))

    def test_creation_like_data_with_extra_keys(self):
        """Посторонние ключи (Address и т.п.) игнорируются валидатором."""
        data = dict(PRODUCTION_PRESET)
        data.update({"ConfigurationName": "AWG", "Address": "10.9.9.0/24",
                     "PrivateKey": "AA=", "Protocol": "awg"})
        self.assertTrue(ValidateAmneziaWGSettings(data)[0])

    def test_uint16_single_and_range(self):
        valid, msg = ValidateAmneziaWGSettings({"Jc": "65535"})
        self.assertTrue(valid, msg)
        valid, msg = ValidateAmneziaWGSettings({"S1": "12-40"})
        self.assertTrue(valid, msg)

    def test_invalid_types_and_out_of_range(self):
        valid, msg = ValidateAmneziaWGSettings({"Jc": "abc"})
        self.assertFalse(valid)
        self.assertIn("Jc", msg)
        valid, msg = ValidateAmneziaWGSettings({"Jc": "99999"})
        self.assertFalse(valid)
        self.assertIn("uint16", msg)
        valid, msg = ValidateAmneziaWGSettings({"H1": "abc"})
        self.assertFalse(valid)
        self.assertIn("H1", msg)
        # 2^31-1 допустимо (uint32); range low > high — нет
        valid, msg = ValidateAmneziaWGSettings({"H1": "2147483647"})
        self.assertTrue(valid, msg)
        valid, msg = ValidateAmneziaWGSettings({"H1": "500-100"})
        self.assertFalse(valid)
        self.assertIn("H1", msg)

    def test_jmax_ge_jmin(self):
        valid, msg = ValidateAmneziaWGSettings({"Jmin": "100", "Jmax": "10"})
        self.assertFalse(valid)
        self.assertIn("Jmax (10) must be >= Jmin (100)", msg)
        valid, msg = ValidateAmneziaWGSettings({"Jmin": "10", "Jmax": "100"})
        self.assertTrue(valid, msg)

    def test_jmax_ge_jmin_merged_with_existing(self):
        existing = {"Jmax": 60}
        valid, msg = ValidateAmneziaWGSettings({"Jmin": "100"}, existing)
        self.assertFalse(valid)
        self.assertIn("Jmax (60) must be >= Jmin (100)", msg)
        valid, msg = ValidateAmneziaWGSettings({"Jmax": "100"}, {"Jmin": "40"})
        self.assertTrue(valid, msg)

    def test_h_ranges_not_overlapping(self):
        params = {"H1": "100-200", "H2": "150-300"}
        valid, msg = ValidateAmneziaWGSettings(params)
        self.assertFalse(valid)
        self.assertIn("overlap", msg)
        params = {"H1": "100-200", "H2": "300-400"}
        self.assertTrue(ValidateAmneziaWGSettings(params)[0])

    def test_h_equal_values_rejected(self):
        valid, msg = ValidateAmneziaWGSettings({"H1": "5", "H2": "5"})
        self.assertFalse(valid)

    def test_h_compat_values_excluded_from_overlap(self):
        params = {"H1": "1", "H2": "2", "H3": "3", "H4": "4"}
        self.assertTrue(ValidateAmneziaWGSettings(params)[0])

    def test_cps_i_params(self):
        valid, msg = ValidateAmneziaWGSettings({"I1": "<b 0xff><t><r 5>"})
        self.assertTrue(valid, msg)
        # <c> существует только в модуля ядра, amneziawg-go его не принимает
        valid, msg = ValidateAmneziaWGSettings({"I2": "<c><t>"})
        self.assertFalse(valid)
        # ограничение длины случайных тегов
        valid, msg = ValidateAmneziaWGSettings({"I3": "<r 2000>"})
        self.assertFalse(valid)
        self.assertIn("1000", msg)

    def test_random_trailers_types(self):
        self.assertTrue(ValidateAmneziaWGSettings({"RandomTrailers": "on"})[0])
        self.assertTrue(ValidateAmneziaWGSettings({"RandomTrailers": "off"})[0])
        # JSON true/false нормализуется в on/off
        self.assertTrue(ValidateAmneziaWGSettings({"RandomTrailers": True})[0])
        valid, msg = ValidateAmneziaWGSettings({"RandomTrailers": "maybe"})
        self.assertFalse(valid)

    def test_header_protection_key_format(self):
        valid, msg = ValidateAmneziaWGSettings({"HeaderProtectionKey": VALID_HPK})
        self.assertTrue(valid, msg)
        hexKey = "0123456789abcdef" * 4
        valid, msg = ValidateAmneziaWGSettings({"HeaderProtectionKey": hexKey})
        self.assertFalse(valid)
        # 64 hex-символа — это корректный base64, но декодируется в 48 байт
        self.assertIn("must decode to 32 bytes", msg)
        valid, msg = ValidateAmneziaWGSettings({"HeaderProtectionKey": "AA=="})
        self.assertFalse(valid)
        self.assertIn("32 bytes", msg)

    def test_hpk_requires_s1_s4_ge_12(self):
        params = dict(PRODUCTION_PRESET)
        params["S1"] = "10"
        valid, msg = ValidateAmneziaWGSettings(params)
        self.assertFalse(valid)
        self.assertIn("S1-S4 >= 12", msg)
        params["S1"] = "12"
        self.assertEqual(ValidateAmneziaWGSettings(params), (True, ""))
        # HPK задан, S-параметры отсутствуют - отсутствие НЕ выводится
        valid, msg = ValidateAmneziaWGSettings({"HeaderProtectionKey": VALID_HPK})
        self.assertTrue(valid, msg)
        # без HPK ограничение не применяется
        valid, msg = ValidateAmneziaWGSettings({"S1": "0"})
        self.assertTrue(valid, msg)

    def test_merged_hpk_check_with_existing(self):
        existing = {"HeaderProtectionKey": VALID_HPK}
        valid, msg = ValidateAmneziaWGSettings({"S2": "5"}, existing)
        self.assertFalse(valid)
        self.assertIn("S2=5", msg)

    def test_h_check_merged_with_existing(self):
        existing = {"H1": "5"}
        valid, msg = ValidateAmneziaWGSettings({"H2": "5"}, existing)
        self.assertFalse(valid)
        self.assertIn("overlap", msg)
        valid, msg = ValidateAmneziaWGSettings({"H2": "6"}, existing)
        self.assertTrue(valid, msg)


class EditApiPathTests(unittest.TestCase):
    """API updateWireguardConfiguration -> updateConfigurationSettings()."""

    def runEdit(self, newData: dict, protocol: str = "awg",
                conf: str = None):
        conf = conf or CONF_TEMPLATE.format(hpk=VALID_HPK)
        inst, tmp, calls, path = makeInstance(conf, protocol=protocol)
        before = path.read_text(encoding="utf-8")
        status, msg = inst.updateConfigurationSettings(dict(newData))
        after = path.read_text(encoding="utf-8")
        return status, msg, before, after, inst, calls, tmp

    def test_bypass_closed_invalid_jc(self):
        status, msg, before, after, inst, calls, tmp = self.runEdit({"Jc": "99999"})
        try:
            self.assertFalse(status, "невалидный Jc должен отклоняться")
            self.assertIn("Jc", msg)
            self.assertEqual(after, before, "файл не должен меняться")
            self.assertEqual(inst.Jc, "5", "атрибут не должен меняться")
            self.assertEqual(calls["toggle"], 0, "интерфейс не должен трогаться")
        finally:
            tmp.cleanup()

    def test_bypass_closed_jmax_lt_jmin(self):
        status, msg, before, after, inst, calls, tmp = self.runEdit({"Jmax": "10"})
        try:
            self.assertFalse(status)
            self.assertIn("Jmax (10) must be >= Jmin (40)", msg)
            self.assertEqual(after, before)
            self.assertEqual(inst.Jmax, "60")
        finally:
            tmp.cleanup()

    def test_bypass_closed_invalid_i_params(self):
        status, msg, before, after, inst, calls, tmp = self.runEdit({"I1": "<c><t>"})
        try:
            self.assertFalse(status)
            self.assertIn("I1", msg)
            self.assertEqual(after, before)
        finally:
            tmp.cleanup()

    def test_valid_edit_applies(self):
        status, msg, before, after, inst, calls, tmp = self.runEdit(
            {"Jc": "20", "S1": "30"})
        try:
            self.assertTrue(status, msg)
            self.assertIn("Jc = 20", after)
            self.assertIn("S1 = 30", after)
            self.assertEqual(inst.Jc, "20")
            self.assertEqual(inst.S1, "30")
            self.assertEqual(calls["toggle"], 1)
        finally:
            tmp.cleanup()

    def test_json_bool_normalization(self):
        status, msg, before, after, inst, calls, tmp = self.runEdit(
            {"RandomTrailers": True})
        try:
            self.assertTrue(status, msg)
            self.assertIn("RandomTrailers = on", after)
            self.assertEqual(inst.RandomTrailers, "on")
        finally:
            tmp.cleanup()

    def test_merged_h_conflict_rejected(self):
        # H1=20/H2=21 (не compat-значения) в файле; правка H2=20 пересекается с H1
        conf = (CONF_TEMPLATE.format(hpk=VALID_HPK)
                .replace("H1 = 1\nH2 = 2\n", "H1 = 20\nH2 = 21\n"))
        status, msg, before, after, inst, calls, tmp = self.runEdit(
            {"H2": "20"}, conf=conf)
        try:
            self.assertFalse(status)
            self.assertIn("overlap", msg)
            self.assertEqual(after, before, "файл не должен меняться")
        finally:
            tmp.cleanup()

    def test_untouched_params_not_revalidated_no_unrelated_freeze(self):
        """Правка несвязанного поля проходит, даже если запрос параметров не содержит."""
        status, msg, before, after, inst, calls, tmp = self.runEdit({"ListenPort": "51820"})
        try:
            self.assertTrue(status, msg)
            self.assertIn("ListenPort = 51820", after)
        finally:
            tmp.cleanup()

    def test_wg_protocol_skips_amnezia_validation(self):
        conf = """[Interface]
PrivateKey = AA=
Address = 10.9.9.0/24
ListenPort = 443

[Peer]
PublicKey = BB=
"""
        status, msg, before, after, inst, calls, tmp = self.runEdit(
            {"ListenPort": "51830"}, protocol="wg", conf=conf)
        try:
            self.assertTrue(status, msg)
            self.assertIn("ListenPort = 51830", after)
        finally:
            tmp.cleanup()


class RawFileApiPathTests(unittest.TestCase):
    """API updateWireguardConfigurationRawFile -> updateRawConfigurationFile()."""

    def runRaw(self, rawText: str, protocol: str = "awg"):
        conf = CONF_TEMPLATE.format(hpk=VALID_HPK)
        inst, tmp, calls, path = makeInstance(conf, protocol=protocol)
        status, msg = inst.updateRawConfigurationFile(rawText)
        return status, msg, inst, calls, path, tmp

    def test_invalid_raw_rejected_without_side_effects(self):
        raw = CONF_TEMPLATE.format(hpk=VALID_HPK).replace("S2 = 21", "S2 = abc")
        status, msg, inst, calls, path, tmp = self.runRaw(raw)
        try:
            self.assertFalse(status, "невалидный raw-файл должен отклоняться")
            self.assertIn("S2", msg)
            # невалидный raw не должен попадать в файл, бэкап не создаётся,
            # интерфейс не пересобирается
            self.assertNotIn("S2 = abc", path.read_text(encoding="utf-8"))
            self.assertEqual(calls["backup"], 0)
            self.assertEqual(calls["toggle"], 0)
        finally:
            tmp.cleanup()

    def test_invalid_raw_jmax_lt_jmin(self):
        raw = CONF_TEMPLATE.format(hpk=VALID_HPK).replace("Jmax = 60", "Jmax = 10")
        status, msg, inst, calls, path, tmp = self.runRaw(raw)
        try:
            self.assertFalse(status)
            self.assertIn("Jmax (10) must be >= Jmin (40)", msg)
            self.assertNotIn("Jmax = 10", path.read_text(encoding="utf-8"))
        finally:
            tmp.cleanup()

    def test_valid_raw_applied(self):
        raw = CONF_TEMPLATE.format(hpk=VALID_HPK).replace("Jc = 5", "Jc = 10")
        status, msg, inst, calls, path, tmp = self.runRaw(raw)
        try:
            self.assertTrue(status, msg)
            self.assertEqual(path.read_text(encoding="utf-8"), raw)
            self.assertEqual(calls["backup"], 1)
            self.assertEqual(calls["toggle"], 1)
        finally:
            tmp.cleanup()

    def test_raw_without_amnezia_params_accepted(self):
        raw = """[Interface]
PrivateKey = AA=
Address = 10.9.9.0/24
ListenPort = 443

[Peer]
PublicKey = BB=
"""
        status, msg, inst, calls, path, tmp = self.runRaw(raw)
        try:
            self.assertTrue(status, msg)
        finally:
            tmp.cleanup()

    def test_raw_wg_protocol_skips_validation(self):
        raw = """[Interface]
PrivateKey = AA=
ListenPort = 443
RandomTrailers = maybe

[Peer]
PublicKey = BB=
"""
        status, msg, inst, calls, path, tmp = self.runRaw(raw, protocol="wg")
        try:
            self.assertTrue(status, msg)
            self.assertEqual(path.read_text(encoding="utf-8"), raw)
        finally:
            tmp.cleanup()


if __name__ == "__main__":
    unittest.main(verbosity=2)

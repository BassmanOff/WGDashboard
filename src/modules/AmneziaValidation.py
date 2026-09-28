"""
AmneziaWG 3.1 Parameter Validation
"""
import base64
import re
import secrets


def ValidateRangeUint16(value: str) -> tuple[bool, str]:
    """Validate uint16 range parameter (e.g., '10-100' or '50')"""
    if value is None or value == "" or value == "0":
        return True, ""
    
    # Single value
    if re.match(r'^\d+$', value):
        v = int(value)
        if 0 <= v <= 65535:
            return True, ""
        return False, f"Value {v} is out of uint16 range (0-65535)"
    
    # Range
    match = re.match(r'^(\d+)-(\d+)$', value)
    if match:
        low, high = int(match.group(1)), int(match.group(2))
        if 0 <= low <= 65535 and 0 <= high <= 65535 and low <= high:
            return True, ""
        return False, f"Invalid range: {value}. Values must be 0-65535 and low <= high"
    
    return False, f"Invalid format: {value}. Use single value or range (e.g., '50' or '10-100')"


def ValidateRangeUint32(value: str) -> tuple[bool, str]:
    """Validate uint32 range parameter (e.g., '100-5000' or '1000')"""
    if value is None or value == "" or value == "0":
        return True, ""
    
    # Single value
    if re.match(r'^\d+$', value):
        v = int(value)
        if 0 <= v <= 4294967295:
            return True, ""
        return False, f"Value {v} is out of uint32 range (0-4294967295)"
    
    # Range
    match = re.match(r'^(\d+)-(\d+)$', value)
    if match:
        low, high = int(match.group(1)), int(match.group(2))
        if 0 <= low <= 4294967295 and 0 <= high <= 4294967295 and low <= high:
            return True, ""
        return False, f"Invalid range: {value}. Values must be 0-4294967295 and low <= high"
    
    return False, f"Invalid format: {value}. Use single value or range (e.g., '1000' or '100-5000')"


def ValidateCPS(value: str) -> tuple[bool, str]:
    """
    Validate CPS (Custom Protocol Signature) format.
    Format: <tag1><tag2><tag3>...<tagN>
    
    Tags:
    - b: <b hex_data> - Static bytes (e.g., <b 0xf6ab3267fa>)
    - t: <t> - Unix timestamp (32-bit)
    - r: <r length> - Random bytes (length <= 1000)
    - rc: <rc N> - Random ASCII letters (N <= 1000)
    - rd: <rd N> - Random decimal digits (N <= 1000)
    """
    if value is None or value == "" or value == "0":
        return True, ""
    
    # Проверяем каждый тег отдельно: <b hex_data>, <t>, <r N>, <rc N>, <rd N>
    # N ограничено 4 цифрами (максимум 1000).
    tag_pattern = re.compile(
        r'<b\s+0x[0-9a-fA-F]+>'      # статические байты
        r'|<t>'                        # unix timestamp
        r'|<r\s+\d{1,4}>'             # случайные байты
        r'|<rc\s+\d{1,4}>'            # случайные ASCII-буквы
        r'|<rd\s+\d{1,4}>'            # случайные цифры
    )

    # Разбираем строку по тегам, отбрасывая разделители
    remainder = value
    foundAny = False
    while len(remainder) > 0:
        match = tag_pattern.match(remainder)
        if match is None:
            return False, (
                f"Invalid CPS format near: '{remainder[:20]}...'. "
                "Valid tags: <b 0xHEX>, <t>, <r N>, <rc N>, <rd N>"
            )
        foundAny = True
        remainder = remainder[match.end():]
        # Пропускаем разделители между тегами (пробелы, запятые)
        stripped = remainder.lstrip(" ,\t")
        if len(stripped) == 0:
            break
        remainder = stripped

    if not foundAny:
        return False, f"Invalid CPS format: {value}. No valid tags found."
    
    # Проверяем ограничения длины для тегов r, rc, rd
    for match in re.finditer(r'<(r|rc|rd)\s+(\d+)>', value):
        tag_type, length = match.group(1), int(match.group(2))
        if length > 1000:
            return False, f"Tag <{tag_type} {length}>: length must be <= 1000"

    return True, ""


def ValidateHeaderProtectionKey(value: str) -> tuple[bool, str]:
    """Validate a 32-byte key in base64 (44 characters, as produced by awg genkey)"""
    if value is None or value == "":
        return True, ""

    try:
        decoded = base64.b64decode(str(value), validate=True)
    except Exception:
        return False, "HeaderProtectionKey must be a base64 string (awg genkey format), not hex"

    if len(decoded) == 32:
        return True, ""

    return False, f"HeaderProtectionKey must decode to 32 bytes, got {len(decoded)}"


def ValidateOnOff(value: str) -> tuple[bool, str]:
    """Validate on/off parameter"""
    if value is None or value == "":
        return True, ""
    
    if value.lower() in ("on", "off"):
        return True, ""
    
    return False, f"Invalid value: {value}. Must be 'on' or 'off'"


def ValidateAmneziaWG31Params(params: dict) -> tuple[bool, dict[str, str]]:
    """
    Validate all AmneziaWG 3.1 parameters.
    
    Returns:
        tuple[bool, dict]: (is_valid, errors_dict)
    """
    errors = {}
    
    # Validate uint16 ranges
    uint16_params = ['Jc', 'Jmin', 'Jmax', 'S1', 'S2', 'S3', 'S4', 'ContentPaddingAddition',
                     'RekeyAfterTime', 'RekeyTimeout', 'RejectAfterTime', 'KeepaliveTimeout',
                     'MaxHandshakeAttempts']
    for param in uint16_params:
        if param in params:
            valid, msg = ValidateRangeUint16(str(params[param]))
            if not valid:
                errors[param] = msg
    
    # Validate uint32 ranges (H1-H4)
    uint32_params = ['H1', 'H2', 'H3', 'H4']
    for param in uint32_params:
        if param in params:
            valid, msg = ValidateRangeUint32(str(params[param]))
            if not valid:
                errors[param] = msg
    
    # Validate CPS parameters (I1-I5)
    cps_params = ['I1', 'I2', 'I3', 'I4', 'I5']
    for param in cps_params:
        if param in params:
            valid, msg = ValidateCPS(str(params[param]))
            if not valid:
                errors[param] = msg
    
    # Validate HeaderProtectionKey
    if 'HeaderProtectionKey' in params:
        valid, msg = ValidateHeaderProtectionKey(str(params['HeaderProtectionKey']))
        if not valid:
            errors['HeaderProtectionKey'] = msg
    
    # Validate on/off parameters
    on_off_params = ['RandomTrailers', 'DisableCookies']
    for param in on_off_params:
        if param in params:
            valid, msg = ValidateOnOff(str(params[param]))
            if not valid:
                errors[param] = msg
    
    return len(errors) == 0, errors


def GenerateHeaderProtectionKey() -> str:
    """
    Случайный 32-байтовый ключ в base64.

    Именно base64, а не hex: в amneziawg-tools ключи разбираются функцией
    parse_key(), которая вызывает key_from_base64(). Hex-строка из 64 символов
    отвергается с "Key is not the correct length or format".
    """
    return base64.b64encode(secrets.token_bytes(32)).decode('ascii')


def ValidateH1H4NonOverlapping(H1: str, H2: str, H3: str, H4: str) -> tuple[bool, str]:
    """
    Validate that H1-H4 ranges do not overlap.
    Note: This is a best-effort check. Full overlap detection for arbitrary ranges is complex.
    """
    def parse_range(value: str) -> tuple[int, int] | None:
        """Возвращает (min, max) или None, если значение отключено/некорректно."""
        value = str(value).strip()
        if len(value) == 0 or value == "0":
            return None
        if '-' in value:
            parts = value.split('-')
            if len(parts) != 2:
                return None
            try:
                low, high = int(parts[0]), int(parts[1])
            except ValueError:
                return None
        else:
            try:
                low = high = int(value)
            except ValueError:
                return None
        if low > high:
            return None
        return low, high
    
    ranges = {}
    for name, val in [('H1', H1), ('H2', H2), ('H3', H3), ('H4', H4)]:
        parsed = parse_range(val)
        if parsed is not None:
            ranges[name] = parsed

    # Значения 1/2/3/4 отключают соответствующий механизм (режим совместимости)
    compat = {'H1': 1, 'H2': 2, 'H3': 3, 'H4': 4}
    for name, disabledValue in compat.items():
        if name in ranges and ranges[name] == (disabledValue, disabledValue):
            del ranges[name]

    names = list(ranges.keys())
    for i in range(len(names)):
        for j in range(i + 1, len(names)):
            r1 = ranges[names[i]]
            r2 = ranges[names[j]]
            if r1[0] <= r2[1] and r2[0] <= r1[1]:
                return False, (
                    f"{names[i]} and {names[j]} ranges overlap: "
                    f"{r1[0]}-{r1[1]} vs {r2[0]}-{r2[1]}"
                )

    return True, ""

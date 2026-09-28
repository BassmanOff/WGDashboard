/**
 * Параметры AmneziaWG и генератор "профиля максимальной защиты от DPI".
 *
 * Вынесено в отдельный модуль, потому что используется в двух местах:
 * newConfiguration.vue (создание) и editConfiguration.vue (редактирование).
 *
 * Диапазоны для таймингов основаны на стандартных значениях WireGuard
 * (REKEY_AFTER=120s, REKEY_TIMEOUT=5s, REJECT_AFTER=90s, KEEPALIVE=30s,
 * MAX_HANDSHAKE_ATTEMPTS=8) с небольшим разбросом. Случайные значения
 * внутри этих диапазонов не дают сессиям выглядеть одинаково для
 * статистического анализа, но остаются в рабочей области.
 */

const randInt = (min, max) => Math.floor(Math.random() * (max - min + 1)) + min;

// Случайное значение или диапазон "a-b" вокруг базового числа base
const randAround = (base, spread) => {
	const low = Math.max(0, base - spread);
	const high = base + spread;
	return low === high ? `${low}` : `${low}-${high}`;
};

/**
 * Описания параметров для подсказок в интерфейсе.
 * isNew: true означает, что параметр появился в AmneziaWG 3.1
 */
export const AMNEZIA_PARAM_INFO = {
	// --- Junk-train (2.0+) ---
	Jc: {isNew: false, text: 'Number of junk packets sent before the handshake. Helps hide the handshake initiation from DPI.'},
	Jmin: {isNew: false, text: 'Minimum junk packet size in bytes.'},
	Jmax: {isNew: false, text: 'Maximum junk packet size in bytes. Must be greater than Jmin for packets to vary in size.'},

	// --- Packet size randomisation (2.0+) ---
	S1: {isNew: false, text: 'Random prefix length in bytes for Handshake Initiation packets.'},
	S2: {isNew: false, text: 'Random prefix length in bytes for Handshake Response packets.'},
	S3: {isNew: false, text: 'Random prefix length in bytes for Cookie packets.'},
	S4: {isNew: false, text: 'Random prefix length in bytes for transport data packets. Increases every data packet by this amount, so reduce peer MTU accordingly.'},

	// --- Message type identifiers (2.0+) ---
	H1: {isNew: false, text: 'Message type identifier or range for Handshake Initiation. Ranges must not overlap with H2, H3 or H4.'},
	H2: {isNew: false, text: 'Message type identifier or range for Handshake Response.'},
	H3: {isNew: false, text: 'Message type identifier or range for Cookie.'},
	H4: {isNew: false, text: 'Message type identifier or range for transport data.'},

	// --- CPS signature packets (2.0+) ---
	I1: {isNew: false, text: 'CPS packet sent before the handshake. Should contain a hex snapshot of a real protocol (e.g. QUIC Initial). Format: <b 0xHEX><rc 10><t><r 50>'},
	I2: {isNew: false, text: 'CPS packet with random bytes. Same format as I1.'},
	I3: {isNew: false, text: 'CPS packet with random bytes. Same format as I1.'},
	I4: {isNew: false, text: 'CPS packet with random bytes. Same format as I1.'},
	I5: {isNew: false, text: 'CPS packet with random bytes. Same format as I1.'},

	// --- AmneziaWG 3.1 ---
	HeaderProtectionKey: {isNew: true, text: '32-byte key (64 hex characters) for Header Protection. Hides unencrypted service fields of WireGuard packets. Requires S1-S4 of at least 12 bytes, and H1-H4 set to 1/2/3/4.'},
	ContentPaddingAddition: {isNew: true, text: 'Adds a random number of bytes (from this range) to transport payloads to defeat statistical padding analysis. Uses free space up to the internal MTU. Keep at 0 unless measured.'},
	RekeyAfterTime: {isNew: true, text: 'Seconds before a session is rekeyed. WireGuard default is 120. Accepts a range to make sessions look less repetitive.'},
	RekeyTimeout: {isNew: true, text: 'Seconds to wait for a handshake response before retrying. WireGuard default is 5.'},
	RejectAfterTime: {isNew: true, text: 'Seconds of silence after which the session is considered dead and a new handshake starts. WireGuard default is 90.'},
	KeepaliveTimeout: {isNew: true, text: 'Seconds of silence after which a keepalive packet is sent. WireGuard default is 30.'},
	MaxHandshakeAttempts: {isNew: true, text: 'Maximum handshake retries before giving up. 0 means unlimited.'},
	RandomTrailers: {isNew: true, text: 'Appends a random number of bytes to packets, so packet size sequences are less predictable. Set S1-S4 to the same value when enabling, otherwise packet types may be misidentified.'},
	DisableCookies: {isNew: true, text: 'Disables sending Handshake Cookie Reply messages. Reduces a fingerprint used in active probing, at the cost of DoS protection.'}
};

/**
 * Генерирует набор параметров для максимальной защиты от DPI.
 * Каждый вызов даёт новые случайные значения, кроме S1-S4, которые
 * по требованию RandomTrailers должны совпадать между собой.
 *
 * @param {boolean} headerProtection - включён ли Header Protection
 * @returns {Object} объект вида {Jc: 5, S1: 20, ...}
 */
export const generateDPIHardenedValues = (headerProtection = true) => {
	// S1-S4: RandomTrailers требует одинаковых значений, Header Protection
	// требует минимум 12 байт. Держим скромно, чтобы не упираться в MTU.
	const S = randInt(12, 32);
	const values = {
		// Junk-train: больше пакетов и шире диапазон размеров - лучше размывает
		// начало сессии
		Jc: randInt(3, 8),
		Jmin: randInt(30, 70),
		Jmax: randInt(600, 1400),

		// Одинаковые S1-S4 обязательны при RandomTrailers
		S1: S,
		S2: S,
		S3: S,
		S4: S,

		// Разброс вокруг стандартных значений WireGuard
		RekeyAfterTime: randAround(120, 15),
		RekeyTimeout: randAround(5, 2),
		RejectAfterTime: randAround(90, 10),
		KeepaliveTimeout: randAround(30, 5),
		MaxHandshakeAttempts: randAround(8, 2),

		// Дополнительное дополнение payload не включаем: оно берёт
		// свободное место до внутреннего MTU и без замеров может
		// привести к проблемам с передачей
		ContentPaddingAddition: '0',

		// Cookie Reply - известный fingerprint при активном зондировании
		DisableCookies: 'on',
		RandomTrailers: 'on',

		// CPS-пакеты оставляем выключенными: осмысленный I1 должен
		// содержать hex-снимок реального протокола, случайный - нет
		I1: '0',
		I2: '0',
		I3: '0',
		I4: '0',
		I5: '0',

		HeaderProtectionKey: ''
	};

	// Заголовки: при Header Protection значения 1/2/3/4 отключают
	// пользовательские заголовки, скрытие делает Header Protection
	if (headerProtection) {
		['H1', 'H2', 'H3', 'H4'].forEach((key, i) => values[key] = i + 1);
	} else {
		// Диапазоны не должны пересекаться
		const rangeSize = randInt(500, 1500);
		let cursor = randInt(10, 100);
		['H1', 'H2', 'H3', 'H4'].forEach((key) => {
			const start = cursor + randInt(1, rangeSize);
			const end = start + randInt(10, rangeSize);
			values[key] = `${start}-${end}`;
			cursor = end;
		});
	}

	return values;
};

/** Рекомендуемый MTU пира для сгенерированного профиля */
export const recommendedMTUFor = (values) => {
	// len(data) = payload + S4, поэтому MTU уменьшается на величину S4
	return 1420 - (parseInt(values.S4, 10) || 0);
};

/** Генерирует 32-байтовый ключ в виде 64 hex-символов */
export const generateRandomKey = () => {
	const array = new Uint8Array(32);
	crypto.getRandomValues(array);
	return Array.from(array, byte => byte.toString(16).padStart(2, '0')).join('');
};

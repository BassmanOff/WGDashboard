<script setup lang="ts">
import {ref, computed} from "vue";
import {fetchGet, fetchPost, getUrl} from "@/utilities/fetch.js";
import {GetLocale} from "@/utilities/locale.js";
import {DashboardConfigurationStore} from "@/stores/DashboardConfigurationStore.js";
import LocaleText from "@/components/text/localeText.vue";

const store = DashboardConfigurationStore()

// fetchGet/fetchPost в проекте callback-ориентированные и не возвращают
// результат, поэтому для VAPID-ключа используем нативный fetch.
const getJson = async (url: string) => {
	const response = await fetch(`${getUrl(url)}`, {
		headers: {"Content-Type": "application/json"}
	})
	if (!response.ok) {
		throw new Error(`HTTP ${response.status}`)
	}
	return await response.json()
}

// base64url -> Uint8Array (ключи PushSubscription приходят в base64url)
const urlB64ToUint8Array = (base64String: string) => {
	const padding = '='.repeat((4 - (base64String.length % 4)) % 4)
	const base64 = (base64String + padding).replace(/-/g, '+').replace(/_/g, '/')
	const rawData = atob(base64)
	return Uint8Array.from([...rawData].map(c => c.charCodeAt(0)))
}

type State = 'unsupported' | 'insecure' | 'denied' | 'default' | 'subscribed' | 'error'

const state = ref<State>('default')
const errorMessage = ref('')
const overdueCount = ref(0)
const deviceCount = ref(0)
const busy = ref(false)

const isSupported = computed(() => {
	return 'serviceWorker' in navigator && 'PushManager' in window && 'Notification' in window
})
// Push API работает только в secure context (HTTPS или localhost)
const isSecure = computed(() => {
	return window.isSecureContext
})

const stateMeta = computed(() => {
	switch (state.value) {
		case 'unsupported':
			return {cls: 'text-bg-secondary', icon: 'bi-x-circle', text: 'Not supported by browser'}
		case 'insecure':
			return {cls: 'text-bg-danger', icon: 'bi-shield-exclamation', text: 'HTTPS required'}
		case 'denied':
			return {cls: 'text-bg-danger', icon: 'bi-bell-slash', text: 'Blocked in browser settings'}
		case 'subscribed':
			return {cls: 'text-bg-success', icon: 'bi-bell-fill', text: 'Notifications enabled'}
		case 'error':
			return {cls: 'text-bg-danger', icon: 'bi-exclamation-triangle', text: 'Error'}
		default:
			return {cls: 'text-bg-warning', icon: 'bi-bell', text: 'Notifications disabled'}
	}
})

const checkState = async () => {
	if (!isSupported.value) {
		state.value = 'unsupported'
		return
	}
	if (!isSecure.value) {
		state.value = 'insecure'
		return
	}
	if (Notification.permission === 'denied') {
		state.value = 'denied'
		return
	}
	try {
		const registration = await navigator.serviceWorker.getRegistration()
		const subscription = await registration?.pushManager?.getSubscription()
		state.value = subscription ? 'subscribed' : 'default'
	} catch (e) {
		state.value = 'default'
	}
	await refreshCounts()
}

const refreshCounts = async () => {
	try {
		await fetchGet('/api/push/status', {}, (res) => {
			if (res.status) {
				overdueCount.value = res.data.overdueClients
				deviceCount.value = res.data.subscriptions
			}
		})
	} catch (e) {
		// не критично
	}
}

// --- Настройки частоты проверки ---
const settings = ref({
	check_interval: 86400,
	expiring_days: 7
})
const savingSettings = ref(false)

const intervalPresets = computed(() => {
	const presets = settings.value.check_interval_presets || [3600, 43200, 86400]
	const current = settings.value.check_interval
	// Если текущее значение задано вне списка пресетов - добавляем его,
	// иначе select покажет пустым
	if (current && !presets.includes(current)) {
		return [...presets, current].sort((a, b) => a - b)
	}
	return presets
})

// Человекочитаемое представление интервала (ключ для локализации)
const formatInterval = (seconds: number) => {
	if (seconds % 86400 === 0) {
		const d = seconds / 86400
		return d === 1 ? 'Every day' : `Every ${d} day(s)`
	}
	if (seconds % 3600 === 0) {
		const h = seconds / 3600
		return h === 1 ? 'Every hour' : `Every ${h} hour(s)`
	}
	return `Every ${Math.round(seconds / 60)} minute(s)`
}

const loadSettings = async () => {
	try {
		const json = await getJson('/api/push/settings')
		settings.value = json.data
	} catch (e) {
		// оставляем значения по умолчанию
	}
}

const saveSettings = async () => {
	savingSettings.value = true
	await fetchPost('/api/push/settings', {
		check_interval: settings.value.check_interval,
		expiring_days: settings.value.expiring_days
	}, (res) => {
		if (res.status) {
			settings.value = {...settings.value, ...res.data}
			store.newMessage("WGDashboard", "Push settings saved", "success")
		} else {
			store.newMessage("WGDashboard", res.message, "danger")
		}
		savingSettings.value = false
	})
}

await loadSettings()

const enableNotifications = async () => {
	if (!isSupported.value || !isSecure.value) return
	busy.value = true
	errorMessage.value = ''
	try {
		const permission = await Notification.requestPermission()
		if (permission !== 'granted') {
			state.value = 'denied'
			errorMessage.value = 'Permission was not granted'
			return
		}

		// Регистрация SW по относительному пути: scope совпадёт с каталогом панели
		const registration = await navigator.serviceWorker.register('./sw.js')
		await navigator.serviceWorker.ready

		const {data: vapidKey} = await getJson('/api/push/vapidPublicKey')

		const subscription = await registration.pushManager.subscribe({
			userVisibleOnly: true,
			applicationServerKey: urlB64ToUint8Array(vapidKey.trim())
		})

		await fetchPost('/api/push/subscribe', {subscription: subscription.toJSON()}, (res) => {
			if (!res.status) {
				errorMessage.value = res.message
			}
		})

		state.value = 'subscribed'
		await refreshCounts()
	} catch (e: any) {
		state.value = 'error'
		errorMessage.value = e?.message || String(e)
	} finally {
		busy.value = false
	}
}

const disableNotifications = async () => {
	busy.value = true
	try {
		const registration = await navigator.serviceWorker.getRegistration()
		const subscription = await registration?.pushManager?.getSubscription()
		if (subscription) {
			await fetchPost('/api/push/unsubscribe', {subscription: subscription.toJSON()}, () => {})
			await subscription.unsubscribe()
		}
		state.value = 'default'
		await refreshCounts()
	} catch (e: any) {
		errorMessage.value = e?.message || String(e)
	} finally {
		busy.value = false
	}
}

const sendTest = async () => {
	busy.value = true
	await fetchPost('/api/push/sendTest', {}, (res) => {
		store.newMessage("WGDashboard", res.status ? res.message : res.message, res.status ? "success" : "danger")
	})
	busy.value = false
}

const checkOverdue = async () => {
	busy.value = true
	await fetchPost('/api/push/checkOverdue', {}, (res) => {
		store.newMessage("WGDashboard", res.status ? res.message : res.message, res.status ? "success" : "danger")
	})
	busy.value = false
}

await checkState()
</script>

<template>
	<div class="d-flex flex-column gap-2">
		<div class="d-flex align-items-center gap-2">
			<span class="badge rounded-pill" :class="stateMeta.cls">
				<i class="bi me-1" :class="stateMeta.icon"></i>
				{{ stateMeta.text }}
			</span>
			<span class="badge text-bg-light ms-auto" v-if="state === 'subscribed'">
				{{ overdueCount }} overdue / {{ deviceCount }} device(s)
			</span>
		</div>

		<div class="alert alert-warning rounded-3 mb-0 py-2 px-3" v-if="state === 'insecure'">
			<small>
				<LocaleText t="Push notifications require HTTPS. Access the dashboard via an HTTPS URL (or localhost) and try again."></LocaleText>
			</small>
		</div>

		<div class="alert alert-danger rounded-3 mb-0 py-2 px-3" v-if="errorMessage">
			<small>{{ errorMessage }}</small>
		</div>

		<div class="d-flex gap-2 flex-wrap">
			<button class="btn btn-sm rounded-3 bg-primary-subtle border-primary-subtle text-primary-emphasis"
			        v-if="state === 'default' || state === 'error'"
			        :disabled="busy || !isSupported || !isSecure"
			        @click="enableNotifications()">
				<i class="bi bi-bell me-1"></i>
				<LocaleText t="Enable notifications"></LocaleText>
			</button>

			<button class="btn btn-sm rounded-3 bg-secondary-subtle border-secondary-subtle text-secondary-emphasis"
			        v-if="state === 'subscribed'"
			        :disabled="busy"
			        @click="disableNotifications()">
				<i class="bi bi-bell-slash me-1"></i>
				<LocaleText t="Disable"></LocaleText>
			</button>

			<button class="btn btn-sm rounded-3 bg-secondary-subtle border-secondary-subtle text-secondary-emphasis"
			        v-if="state === 'subscribed'"
			        :disabled="busy"
			        @click="sendTest()">
				<i class="bi bi-send me-1"></i>
				<LocaleText t="Send test"></LocaleText>
			</button>

			<button class="btn btn-sm rounded-3 bg-secondary-subtle border-secondary-subtle text-secondary-emphasis"
			        :disabled="busy"
			        @click="checkOverdue()">
				<i class="bi bi-cash-coin me-1"></i>
				<LocaleText t="Check overdue now"></LocaleText>
			</button>
		</div>

		<hr>

		<div class="d-flex flex-column gap-2">
			<div class="d-flex align-items-center gap-2">
				<i class="bi bi-clock-history text-muted"></i>
				<strong class="small">
					<LocaleText t="Check frequency"></LocaleText>
				</strong>
			</div>
			<div class="row g-2">
				<div class="col-sm-6">
					<label class="form-label">
						<small class="text-muted">
							<LocaleText t="Check interval"></LocaleText>
						</small>
					</label>
					<select class="form-select form-select-sm rounded-3"
					        v-model.number="settings.check_interval"
					        :disabled="savingSettings">
						<option :value="seconds"
						        v-for="seconds in intervalPresets"
						        :key="seconds">
							{{ GetLocale(formatInterval(seconds)) }}
						</option>
					</select>
				</div>
				<div class="col-sm-6">
					<label class="form-label">
						<small class="text-muted">
							<LocaleText t="Warn days before expiry"></LocaleText>
						</small>
					</label>
					<input type="number" min="0" max="90"
					       class="form-control form-control-sm rounded-3"
					       v-model.number="settings.expiring_days"
					       :disabled="savingSettings">
					<div class="form-text">
						<LocaleText t="0 = only overdue payments"></LocaleText>
					</div>
				</div>
			</div>
			<div>
				<button class="btn btn-sm rounded-3 bg-primary-subtle border-primary-subtle text-primary-emphasis"
				        :disabled="savingSettings"
				        @click="saveSettings()">
					<i class="bi bi-save-fill me-1"></i>
					<LocaleText t="Save"></LocaleText>
				</button>
			</div>
		</div>

		<small class="text-muted">
			<LocaleText t="You will get a notification on this device when a client's payment is overdue or about to expire. For notifications to arrive, keep WGDashboard installed as an app (Add to Home Screen)."></LocaleText>
		</small>
	</div>
</template>

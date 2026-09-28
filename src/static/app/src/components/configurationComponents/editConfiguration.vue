<script setup>
import LocaleText from "@/components/text/localeText.vue";
import {reactive, ref, watch} from "vue";
import {WireguardConfigurationsStore} from "@/stores/WireguardConfigurationsStore.js";
import {fetchPost} from "@/utilities/fetch.js";
import {DashboardConfigurationStore} from "@/stores/DashboardConfigurationStore.js";
import UpdateConfigurationName
	from "@/components/configurationComponents/editConfigurationComponents/updateConfigurationName.vue";
import EditRawConfigurationFile
	from "@/components/configurationComponents/editConfigurationComponents/editRawConfigurationFile.vue";
import DeleteConfiguration from "@/components/configurationComponents/deleteConfiguration.vue";
import ConfigurationBackupRestore from "@/components/configurationComponents/configurationBackupRestore.vue";
import EditPeerSettingsOverride
	from "@/components/configurationComponents/editConfigurationComponents/editPeerSettingsOverride.vue";
import {
	AMNEZIA_PARAM_INFO as AMNEZIA_PARAM_INFO_MAP,
	generateDPIHardenedValues,
	recommendedMTUFor,
	generateRandomKey
} from "@/utilities/amneziaParams.js";
const props = defineProps({
	configurationInfo: Object
})
const wgStore = WireguardConfigurationsStore()
const AMNEZIA_PARAM_INFO = AMNEZIA_PARAM_INFO_MAP
const store = DashboardConfigurationStore()
const saving = ref(false)
const data = reactive(JSON.parse(JSON.stringify(props.configurationInfo)))
const editPrivateKey = ref(false)
const dataChanged = ref(false)
const reqField = reactive({
	PrivateKey: true,
	IPAddress: true,
	ListenPort: true
})
const genKey = () => {
	if (wgStore.checkWGKeyLength(data.PrivateKey)){
		reqField.PrivateKey = true;
		data.PublicKey = window.wireguard.generatePublicKey(data.PrivateKey)
	}else{
		reqField.PrivateKey = false;
	}
}
const generateHeaderProtectionKey = () => {
	data.HeaderProtectionKey = generateRandomKey();
}
const headerProtectionEnabled = ref(true)
const profileGenerated = ref(false)
const recommendedMTU = ref(1400)

// Диапазоны H1-H4 не должны пересекаться (AmneziaWG 3.1)
const generateHeaderValues = () => {
	const values = generateDPIHardenedValues(false);
	['H1', 'H2', 'H3', 'H4'].forEach(k => data[k] = values[k]);
}

const applyDPIHardenedProfile = () => {
	// Генератор берёт новые случайные значения при каждом вызове,
	// сохраняя инварианты (см. utilities/amneziaParams.js)
	const values = generateDPIHardenedValues(headerProtectionEnabled.value);
	Object.assign(data, values);
	if (headerProtectionEnabled.value){
		data.HeaderProtectionKey = generateRandomKey();
	}
	recommendedMTU.value = recommendedMTUFor(values);
	profileGenerated.value = true;
	dataChanged.value = true;
	store.newMessage(
		"WGDashboard",
		`DPI-hardened profile applied. Recommended peer MTU: ${recommendedMTU.value}`,
		"success"
	)
}
const resetForm = () => {
	dataChanged.value = false;
	Object.assign(data, JSON.parse(JSON.stringify(props.configurationInfo)))
}
const emit = defineEmits(["changed", "close", "refresh", "dataChanged"])
// Диапазоны H1-H4 не должны пересекаться (AmneziaWG 3.1)
const validateHeaderRanges = () => {
	if (props.configurationInfo.Protocol !== 'awg') return true;
	const parse = (value) => {
		const str = String(value ?? '').trim();
		if (str === '' || str === '0') return null;
		const parts = str.split('-');
		if (parts.length === 1) {
			const n = parseInt(parts[0], 10);
			return Number.isNaN(n) ? null : [n, n];
		}
		const low = parseInt(parts[0], 10);
		const high = parseInt(parts[1], 10);
		if (Number.isNaN(low) || Number.isNaN(high) || low > high) return null;
		return [low, high];
	};
	// Значения 1/2/3/4 отключают механизм и проверке не подлежат
	const compat = {H1: 1, H2: 2, H3: 3, H4: 4};
	const ranges = {};
	['H1', 'H2', 'H3', 'H4'].forEach((key) => {
		const parsed = parse(data[key]);
		if (parsed === null) return;
		if (parsed[0] === parsed[1] && parsed[0] === compat[key]) return;
		ranges[key] = parsed;
	});
	const names = Object.keys(ranges);
	for (let i = 0; i < names.length; i++) {
		for (let j = i + 1; j < names.length; j++) {
			const a = ranges[names[i]];
			const b = ranges[names[j]];
			if (a[0] <= b[1] && b[0] <= a[1]) {
				store.newMessage("Server", `${names[i]} (${a[0]}-${a[1]}) and ${names[j]} (${b[0]}-${b[1]}) ranges overlap`, "danger");
				return false;
			}
		}
	}
	return true;
}

const saveForm = ()  => {
	if (!validateHeaderRanges()) return;
	saving.value = true
	fetchPost("/api/updateWireguardConfiguration", data, (res) => {
		saving.value = false
		if (res.status){
			store.newMessage("Server", "Configuration saved", "success")
			dataChanged.value = false
			emit("dataChanged", res.data)
			
		}else{
			store.newMessage("Server", res.message, "danger")
		}
	})
}
const updateConfigurationName = ref(false)

watch(data, () => {
	dataChanged.value = JSON.stringify(data) !== JSON.stringify(props.configurationInfo);
}, {
	deep: true
})

const editRawConfigurationFileModal = ref(false)
const backupRestoreModal = ref(false)
const deleteConfigurationModal = ref(false)


</script>

<template>
	<div class="peerSettingContainer w-100 h-100 position-absolute top-0 start-0" ref="editConfigurationContainer">
		<div class="w-100 h-100  overflow-y-scroll">
			<TransitionGroup name="zoom">
				<EditRawConfigurationFile
					name="EditRawConfigurationFile"
					v-if="editRawConfigurationFileModal"
					@close="editRawConfigurationFileModal = false">
				</EditRawConfigurationFile>
				<DeleteConfiguration
					key="DeleteConfiguration"
					@backup="backupRestoreModal = true"
					@close="deleteConfigurationModal = false"
					v-if="deleteConfigurationModal">
				</DeleteConfiguration>
				<ConfigurationBackupRestore
					@close="backupRestoreModal = false"
					@refreshPeersList="emit('refresh')"
					v-if="backupRestoreModal">
				</ConfigurationBackupRestore>
			</TransitionGroup>

			<div class="container d-flex h-100 w-100">
				<div class="m-auto modal-dialog-centered dashboardModal" style="width: 700px">
					<div class="card rounded-3 shadow flex-grow-1">
						<div class="card-header bg-transparent d-flex align-items-center gap-2 border-0 p-4">
							<h4 class="mb-0">
								<LocaleText t="Configuration Settings"></LocaleText>
							</h4>
							<button type="button" class="btn-close ms-auto" @click="$emit('close')"></button>
						</div>
						<div class="card-body px-4 pb-4">
							<div class="d-flex gap-2 flex-column">
								<div class="d-flex align-items-center gap-3" v-if="!updateConfigurationName">
									<small class="text-muted">
										<LocaleText t="Name"></LocaleText>
									</small>
									<small>{{data.Name}}</small>
									<button
										@click="updateConfigurationName = true"
										class="btn btn-sm bg-danger-subtle border-danger-subtle text-danger-emphasis rounded-3 ms-auto">
										<LocaleText t="Update Name"></LocaleText>
									</button>
								</div>
								<UpdateConfigurationName
									@close="updateConfigurationName = false"
									:configuration-name="data.Name"
									v-if="updateConfigurationName"></UpdateConfigurationName>
								<template v-else>
									<hr>
									<div class="d-flex align-items-center gap-3">
										<small class="text-muted" style="word-break: keep-all">
											<LocaleText t="Public Key"></LocaleText>
										</small>
										<small class="ms-auto"  style="word-break: break-all">
											{{data.PublicKey}}
										</small>
									</div>
									<hr>
									<div>
										<div class="d-flex">
											<label for="configuration_private_key" class="form-label">
												<small class="text-muted d-block">
													<LocaleText t="Private Key"></LocaleText>
												</small>
											</label>
											<div class="form-check form-switch ms-auto">
												<input class="form-check-input"
												       type="checkbox" role="switch" id="editPrivateKeySwitch"
												       v-model="editPrivateKey"
												>
												<label class="form-check-label" for="editPrivateKeySwitch">
													<small>Edit</small>
												</label>
											</div>
										</div>
										<input type="text" class="form-control form-control-sm rounded-3"
										       :disabled="saving || !editPrivateKey"
										       :class="{'is-invalid': !reqField.PrivateKey}"
										       @keyup="genKey()"
										       v-model="data.PrivateKey"
										       id="configuration_private_key">
									</div>
									<div>
										<label for="configuration_ipaddress_cidr" class="form-label">
											<small class="text-muted">
												<LocaleText t="IP Address/CIDR"></LocaleText>
											</small>
										</label>
										<input type="text" class="form-control form-control-sm rounded-3"
										       :disabled="saving"
										       v-model="data.Address"
										       id="configuration_ipaddress_cidr">
									</div>
									<div>
										<label for="configuration_listen_port" class="form-label">
											<small class="text-muted">
												<LocaleText t="Listen Port"></LocaleText>
											</small>
										</label>
										<input type="number" class="form-control form-control-sm rounded-3"
										       :disabled="saving"
										       v-model="data.ListenPort"
										       id="configuration_listen_port">

									</div>
									<div class="accordion mt-2" id="editConfigurationOptionalAccordion">
										<div class="accordion-item">
											<h2 class="accordion-header">
												<button class="accordion-button collapsed px-3 py-2" type="button" data-bs-toggle="collapse" data-bs-target="#editOptionalAccordionCollapse">
													<small class="text-muted">
														<LocaleText t="Optional Settings"></LocaleText>
													</small>
												</button>
											</h2>
											<div id="editOptionalAccordionCollapse"
											     class="accordion-collapse collapse" data-bs-parent="#editConfigurationOptionalAccordion">
												<div class="accordion-body d-flex flex-column gap-3">
													<!-- Пресет максимальной защиты от DPI -->
													<div v-if="configurationInfo.Protocol === 'awg'"
													     class="p-3 rounded-3 border border-primary">
														<div class="d-flex align-items-center gap-2 mb-2">
															<i class="bi bi-shield-lock-fill text-primary"></i>
															<strong class="small">
																<LocaleText t="DPI hardened profile"></LocaleText>
															</strong>
															<span class="badge rounded-pill text-bg-primary ms-auto">AWG 3.1</span>
														</div>
														<small class="text-muted d-block mb-2">
															<LocaleText t="Fills in the parameters recommended by the AmneziaWG 3.1 documentation for maximum protection against DPI detection. You can adjust any value afterwards."></LocaleText>
														</small>
														<div class="form-check form-switch mb-2">
															<input class="form-check-input" type="checkbox" role="switch"
															       id="editHeaderProtectionEnabled"
															       v-model="headerProtectionEnabled">
															<label class="form-check-label" for="editHeaderProtectionEnabled">
																<LocaleText t="Enable Header Protection (sets H1-H4 to 1/2/3/4)"></LocaleText>
															</label>
														</div>
														<button class="btn btn-primary btn-sm rounded-3"
														        type="button"
														        :disabled="saving"
														        @click="applyDPIHardenedProfile()">
															<i class="bi bi-magic me-1"></i>
															<LocaleText t="Apply maximum DPI protection"></LocaleText>
														</button>
														<div class="form-text mt-1" v-if="profileGenerated">
															<LocaleText :t="'Set peer MTU to ' + recommendedMTU + ' to avoid fragmentation.'"></LocaleText>
														</div>
													</div>
													<div v-for="key in ['Table', 'PreUp', 'PreDown', 'PostUp', 'PostDown']">
														<label :for="'configuration_' + key" class="form-label">
															<small class="text-muted">
																<LocaleText :t="key"></LocaleText>
															</small>
														</label>
														<input type="text" class="form-control form-control-sm rounded-3"
														       :disabled="saving"
														       v-model="data[key]"
														       :id="'configuration_' + key">
													</div>
													<!-- AmneziaWG 2.0+ parameters -->
													<div v-for="key in ['Jc', 'Jmin', 'Jmax', 'S1', 'S2', 'S3', 'S4', 'H1', 'H2', 'H3', 'H4', 'I1', 'I2', 'I3', 'I4', 'I5']"
													     v-if="configurationInfo.Protocol === 'awg'">
														<label :for="'configuration_' + key" class="form-label">
															<small class="text-muted">
																<LocaleText :t="key"></LocaleText>
															</small>
														</label>
														<input type="text" class="form-control form-control-sm rounded-3"
														       :disabled="saving"
														       v-model="data[key]"
														       :id="'configuration_' + key">
														<div class="form-text" v-if="AMNEZIA_PARAM_INFO[key]">
															<LocaleText :t="AMNEZIA_PARAM_INFO[key].text"></LocaleText>
														</div>
													</div>
													
													<!-- AmneziaWG 3.1 new parameters -->
													<div v-if="configurationInfo.Protocol === 'awg'">
														<label for="configuration_HeaderProtectionKey" class="form-label">
															<small class="text-muted">HeaderProtectionKey</small>
														</label>
														<div class="input-group input-group-sm">
															<input type="text" class="form-control form-control-sm rounded-3 font-monospace"
															       :disabled="saving"
															       v-model="data.HeaderProtectionKey"
															       id="configuration_HeaderProtectionKey"
															       placeholder="64 hex characters (32 bytes)">
															<button class="btn btn-outline-primary btn-sm" type="button"
															        @click="generateHeaderProtectionKey()">
																<i class="bi bi-arrow-repeat"></i>
															</button>
														</div>
														<div class="form-text">32-byte key for Header Protection (ChaCha20)</div>
													</div>
													
													<div v-for="key in ['ContentPaddingAddition', 'RekeyAfterTime', 'RekeyTimeout', 'RejectAfterTime', 'KeepaliveTimeout', 'MaxHandshakeAttempts']"
													     v-if="configurationInfo.Protocol === 'awg'">
														<label :for="'configuration_' + key" class="form-label d-flex align-items-center gap-2">
															<small class="text-muted">
																<LocaleText :t="key"></LocaleText>
															</small>
															<span class="badge rounded-pill text-bg-info">AWG 3.1</span>
														</label>
														<input type="text" class="form-control form-control-sm rounded-3 font-monospace"
														       :disabled="saving"
														       v-model="data[key]"
														       :id="'configuration_' + key"
														       placeholder="e.g., 10-100 or 50">
														<div class="form-text" v-if="AMNEZIA_PARAM_INFO[key]">
															<LocaleText :t="AMNEZIA_PARAM_INFO[key].text"></LocaleText>
														</div>
													</div>
												
													<div v-for="key in ['RandomTrailers', 'DisableCookies']"
													     v-if="configurationInfo.Protocol === 'awg'">
														<label :for="'configuration_' + key" class="form-label d-flex align-items-center gap-2">
															<small class="text-muted">
																<LocaleText :t="key"></LocaleText>
															</small>
															<span class="badge rounded-pill text-bg-info">AWG 3.1</span>
														</label>
														<select class="form-select form-select-sm rounded-3"
														        :disabled="saving"
														        v-model="data[key]"
														        :id="'configuration_' + key">
															<option value="off">off</option>
															<option value="on">on</option>
														</select>
													</div>
												</div>
											</div>
										</div>
									</div>
									<div class="d-flex align-items-center gap-2 mt-1">
										<button class="btn btn-sm bg-secondary-subtle border-secondary-subtle text-secondary-emphasis rounded-3 shadow ms-auto"
										        @click="resetForm()"
										        :disabled="!dataChanged || saving">
											<i class="bi bi-arrow-clockwise me-2"></i>
											<LocaleText t="Reset"></LocaleText>
										</button>
										<button class="btn btn-sm bg-primary-subtle border-primary-subtle text-primary-emphasis rounded-3 shadow"
										        :disabled="!dataChanged || saving"
										        @click="saveForm()"
										>
											<i class="bi bi-save-fill me-2"></i>
											<LocaleText t="Save"></LocaleText>
										</button>
									</div>
									<hr>
									<EditPeerSettingsOverride :configuration="configurationInfo"></EditPeerSettingsOverride>
									<hr>
									<h5 class="mb-3">
										<LocaleText t="Danger Zone"></LocaleText>
									</h5>
									<div class="d-flex gap-2 flex-column">
										<button
											@click="backupRestoreModal = true"
											class="btn bg-warning-subtle border-warning-subtle text-warning-emphasis rounded-3 text-start d-flex">
											<i class="bi bi-copy me-auto"></i>
											<LocaleText t="Backup & Restore"></LocaleText>
										</button>
										<button
											@click="editRawConfigurationFileModal = true"
											class="btn bg-warning-subtle border-warning-subtle text-warning-emphasis rounded-3 d-flex">
											<i class="bi bi-pen me-auto"></i>
											<LocaleText t="Edit Raw Configuration File"></LocaleText>
										</button>

										<button
											@click="deleteConfigurationModal = true"
											class="btn bg-danger-subtle border-danger-subtle text-danger-emphasis rounded-3 d-flex mt-4">
											<i class="bi bi-trash-fill me-auto"></i>
											<LocaleText t="Delete Configuration"></LocaleText>
										</button>
									</div>
								</template>
							</div>
						</div>
					</div>
				</div>
			</div>
		</div>
	</div>
</template>

<style scoped>

</style>
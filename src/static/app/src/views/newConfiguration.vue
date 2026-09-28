<script>
import {parseCidr, containsCidr, mergeCidr, expandCidr} from "cidr-tools";
import '@/utilities/wireguard.js'
import {WireguardConfigurationsStore} from "@/stores/WireguardConfigurationsStore.js";
import {fetchGet, fetchPost} from "@/utilities/fetch.js";
import LocaleText from "@/components/text/localeText.vue";
import {parseInterface, parsePeers} from "@/utilities/parseConfigurationFile.js";
import {ref} from "vue";
import {DashboardConfigurationStore} from "@/stores/DashboardConfigurationStore.js";
import {exp} from "qrcode/lib/core/galois-field.js";
import NewConfigurationTemplates from "@/components/newConfigurationComponents/newConfigurationTemplates.vue";
import {
	AMNEZIA_PARAM_INFO,
	generateDPIHardenedValues,
	recommendedMTUFor,
	generateRandomKey
} from "@/utilities/amneziaParams.js";

export default {
	name: "newConfiguration",
	components: {NewConfigurationTemplates, LocaleText},
	async setup(){
		const store = WireguardConfigurationsStore()
		const protocols = ref([])
		await fetchGet("/api/protocolsEnabled", {}, (res) => {
			protocols.value = res.data
		})
		const dashboardStore = DashboardConfigurationStore();
		
		return {store, protocols, dashboardStore, AMNEZIA_PARAM_INFO}
	},
	data(){
		return {
			newConfiguration: {
				ConfigurationName: "",
				Address: "",
				ListenPort: "",
				PrivateKey: "",
				PublicKey: "",
				PresharedKey: "",
				PreUp: "",
				PreDown: "",
				PostUp: "",
				PostDown: "",
				Table: "",
				Protocol: "wg",
				// AmneziaWG 2.0+ parameters
				Jc: 5,
				Jmin: 49,
				Jmax: 998,
				S1: 17,
				S2: 110,
				S3: 1,
				S4: 2,
				H1: 0,
				H2: 0,
				H3: 0,
				H4: 0,
				I1: "0",
				I2: "0",
				I3: "0",
				I4: "0",
				I5: "0",
				// AmneziaWG 3.1 new parameters
				HeaderProtectionKey: "",
				ContentPaddingAddition: "0",
				RekeyAfterTime: "0",
				RekeyTimeout: "0",
				RejectAfterTime: "0",
				KeepaliveTimeout: "0",
				MaxHandshakeAttempts: "0",
				RandomTrailers: "off",
				DisableCookies: "off"
			},
			numberOfAvailableIPs: "0",
			error: false,
			errorMessage: "",
			success: false,
			loading: false,
			profileGenerated: false,
			recommendedMTU: 1400,
			headerProtectionEnabled: true,
			parseInterfaceResult: undefined,
			parsePeersResult: undefined
		}
	},
	created() {
		this.wireguardGenerateKeypair();

		// Generate 4 non-overlapping random ranges for H1, H2, H3, H4.
		// Per AmneziaWG 3.1 docs the ranges must not intersect each other.
		// Values 1/2/3/4 disable the corresponding mechanism, so we start from 10.
		this.generateHeaderValues();

		// Initialize I1 to I5 as "0"
		['I1', 'I2', 'I3', 'I4', 'I5'].forEach(key => {
			this.newConfiguration[key] = "0";
		});
	},
	methods: {
		rand(min, max){
			return Math.floor(Math.random() * (max - min) + min);
		},
		wireguardGenerateKeypair(){
			const wg = window.wireguard.generateKeypair();
			this.newConfiguration.PrivateKey = wg.privateKey;
			this.newConfiguration.PublicKey = wg.publicKey;
			this.newConfiguration.PresharedKey = wg.presharedKey;
		},
		generateHeaderValues(){
			// 4 непересекающихся диапазона (Header Protection выключен)
			const values = generateDPIHardenedValues(false);
			['H1', 'H2', 'H3', 'H4'].forEach(k => this.newConfiguration[k] = values[k]);
		},
		generateHeaderProtectionKey(){
			this.newConfiguration.HeaderProtectionKey = generateRandomKey();
		},
		generateDPIHardenedProfile(){
			// Каждый вызов даёт новые случайные значения. Инварианты,
			// которые соблюдает генератор (см. utilities/amneziaParams.js):
			//  - S1-S4 >= 12 байт, иначе не работает Header Protection
			//  - S1-S4 одинаковые, иначе при RandomTrailers тип пакета
			//    может определяться неверно
			//  - при Header Protection H1-H4 = 1/2/3/4
			//  - при выключенном - диапазоны не пересекаются
			const values = generateDPIHardenedValues(this.headerProtectionEnabled);
			Object.assign(this.newConfiguration, values);
			if (this.headerProtectionEnabled){
				this.newConfiguration.HeaderProtectionKey = generateRandomKey();
			}

			this.recommendedMTU = recommendedMTUFor(values);
			this.profileGenerated = true;
			this.dashboardStore.newMessage(
				"WGDashboard",
				`DPI-hardened profile applied. Recommended peer MTU: ${this.recommendedMTU}`,
				"success"
			);
		},
		async saveNewConfiguration(){
			if (this.goodToSubmit){
				this.loading = true;
				await fetchPost("/api/addWireguardConfiguration", this.newConfiguration, async (res) => {
					if (res.status){
						this.success = true
						await this.store.getConfigurations()
						this.$router.push(`/configuration/${this.newConfiguration.ConfigurationName}/peers`)
					}else{
						this.error = true;
						this.errorMessage = res.message;
						document.querySelector(`#${res.data}`).classList.remove("is-valid")
						document.querySelector(`#${res.data}`).classList.add("is-invalid")
						this.loading = false;
					}
				})
			}
		},
		openFileUpload(){
			document.querySelector("#fileUpload").click();
		},
		readFile(e){
			const file = e.target.files[0];
			if (!file) return false;
			const reader = new FileReader();
			reader.onload = (evt) => {
				this.parseInterfaceResult = parseInterface(evt.target.result);
				this.parsePeersResult = parsePeers(evt.target.result);
				let appliedFields = 0;
				if (this.parseInterfaceResult){
					this.newConfiguration.ConfigurationName = file.name.replace('.conf', '')
					for (let i of Object.keys(this.parseInterfaceResult)){
						if (Object.keys(this.newConfiguration).includes(i)){
							this.newConfiguration[i] = this.parseInterfaceResult[i];
							appliedFields += 1;
						}
					}
				}
				if (appliedFields > 0){
					this.dashboardStore.newMessage("WGDashboard", `Parse successful! Updated ${appliedFields} field(s)`, "success")
				}else {
					this.dashboardStore.newMessage("WGDashboard", `Parse failed`, "danger")
				}
			};
			reader.readAsText(file);
		}
	},
	computed: {
		goodToSubmit(){
			let requirements = ["ConfigurationName", "Address", "ListenPort", "PrivateKey"]
			let elements = [...document.querySelectorAll("input[required]")];
			return requirements.find(x => {
				return this.newConfiguration[x].length === 0
			}) === undefined && elements.find(x => {
				return x.classList.contains("is-invalid")
			}) === undefined
		}
	},
	watch: {
		'newConfiguration.Address'(newVal){
			let ele = document.querySelector("#Address");
			if (ele){
				ele.classList.remove("is-invalid", "is-valid")
				try{
					this.numberOfAvailableIPs = 0
					newVal.replace(" ", "").split(",").forEach(x => {
						let p = parseCidr(x);
						let i = Number(p.end - p.start);
						this.numberOfAvailableIPs += i + 1;
					})
					ele.classList.add("is-valid")
				}catch (e) {
					console.log(e)
					this.numberOfAvailableIPs = "0";
					ele.classList.add("is-invalid")
				}
			}
		},
		'newConfiguration.ListenPort'(newVal){
			let ele = document.querySelector("#ListenPort");
			if (ele){
				ele.classList.remove("is-invalid", "is-valid")

				if (newVal < 0 || newVal > 65353 || !Number.isInteger(newVal)){
					ele.classList.add("is-invalid")
				}else{
					ele.classList.add("is-valid")
				}
			}
		},
		'newConfiguration.ConfigurationName'(newVal){
			let ele = document.querySelector("#ConfigurationName");
			if (ele){
				ele.classList.remove("is-invalid", "is-valid")
				if (!/^[a-zA-Z0-9_=+.-]{1,15}$/.test(newVal) || newVal.length === 0 || this.store.Configurations.find(x => x.Name === newVal)){
					ele.classList.add("is-invalid")
				}else{
					ele.classList.add("is-valid")
				}
			}
		},
		'newConfiguration.PrivateKey'(newVal){
			let ele = document.querySelector("#PrivateKey");
			if (ele){
				ele.classList.remove("is-invalid", "is-valid")

				try{
					wireguard.generatePublicKey(newVal)
					ele.classList.add("is-valid")
				}catch (e) {
					ele.classList.add("is-invalid")
				}
			}
		}
	},
	mounted() {
		const fileUpload = document.querySelector("#fileUpload");
		fileUpload.addEventListener("change", this.readFile, false)
	}
}
</script>

<template>
	<div class="mt-md-5 mt-3 text-body">
		<div class="container mb-4">
			<div class="mb-4 d-flex align-items-center gap-4 align-items-center">
				<RouterLink to="/"
				            class="btn btn-dark btn-brand p-2 shadow" style="border-radius: 100%">
					<h2 class="mb-0" style="line-height: 0">
						<i class="bi bi-arrow-left-circle"></i>
					</h2>
				</RouterLink>
				<h2 class="mb-0">
					<LocaleText t="New Configuration"></LocaleText>
				</h2>
				<div class="d-flex gap-2 ms-auto">
					<button class="titleBtn py-2 text-decoration-none btn text-primary-emphasis bg-primary-subtle rounded-3 border-1 border-primary-subtle"
					        @click="openFileUpload()"
					        type="button" aria-expanded="false">
						<i class="bi bi-upload me-2"></i>
						<LocaleText t="Open File"></LocaleText>
					</button>
					<input type="file" id="fileUpload" multiple class="d-none" accept="text/plain" />
				</div>
			</div>
			
			<form class="text-body d-flex flex-column gap-3"
				@submit="(e) => {e.preventDefault(); this.saveNewConfiguration();}"
			>
				<div class="card rounded-3 shadow">
					<div class="card-header">
						<LocaleText t="Protocol"></LocaleText>
					</div>
					<div class="card-body d-flex gap-2 protocolBtnGroup">
						<a 
							v-if="this.protocols.includes('wg')"
							@click="this.newConfiguration.Protocol = 'wg'"
							:class="{'opacity-50': this.newConfiguration.Protocol !== 'wg'}"
							class="btn btn-primary wireguardBg border-0 " style="flex-basis: 100%">
							<i class="bi bi-check-circle-fill me-2" v-if="this.newConfiguration.Protocol === 'wg'"></i>
							<i class="bi bi-circle me-2" v-else></i>
							<strong>
								WireGuard
							</strong>
						</a>
						<a
							@click="this.newConfiguration.Protocol = 'awg'"
							v-if="this.protocols.includes('awg')"
							:class="{'opacity-50': this.newConfiguration.Protocol !== 'awg'}"
							class="btn btn-primary amneziawgBg border-0" style="flex-basis: 100%">
							<i class="bi bi-check-circle-fill me-2" v-if="this.newConfiguration.Protocol === 'awg'"></i>
							<i class="bi bi-circle me-2" v-else></i>
							<strong>
								AmneziaWG
							</strong>
						</a>
					</div>
				</div>
				
				<div class="card rounded-3 shadow">
					<div class="card-header">
						<LocaleText t="Configuration Name"></LocaleText>
					</div>
					<div class="card-body">
						<input type="text" class="form-control" placeholder="ex. wg1" id="ConfigurationName" 
						       v-model="this.newConfiguration.ConfigurationName"
						       :disabled="this.loading"
						       required>
						<div class="invalid-feedback">
							<div v-if="this.error">{{this.errorMessage}}</div>
							<div v-else>
								<LocaleText t="Configuration name is invalid. Possible reasons:"></LocaleText>
								<ul class="mb-0">
									<li>
										<LocaleText t="Configuration name already exist."></LocaleText>
									</li>
									<li>
										<LocaleText t="Configuration name can only contain 15 lower/uppercase alphabet, numbers, underscore, equal sign, plus sign, period and hyphen."></LocaleText>
									</li>
								</ul>
							</div>
						</div>
					</div>
				</div>
				<div class="card rounded-3 shadow">
					<div class="card-header">
						<LocaleText t="Private Key"></LocaleText> & <LocaleText t="Public Key"></LocaleText>
					</div>
					<div class="card-body" style="font-family: var(--bs-font-monospace)">
						<div class="mb-2">
							<label class="text-muted fw-bold mb-1"><small>
								<LocaleText t="Private Key"></LocaleText>
							</small></label>
							<div class="input-group">
								<input type="text" class="form-control" id="PrivateKey" required
								       :disabled="this.loading"
								       v-model="this.newConfiguration.PrivateKey" disabled
								>
								<button class="btn btn-outline-primary" type="button"
								        title="Regenerate Private Key"
								        @click="wireguardGenerateKeypair()"
								>
									<i class="bi bi-arrow-repeat"></i>
								</button>
							</div>
						</div>
						<div>
							<label class="text-muted fw-bold mb-1"><small>
								<LocaleText t="Public Key"></LocaleText>
							</small></label>
							<input type="text" class="form-control" id="PublicKey"
							       v-model="this.newConfiguration.PublicKey" disabled
							>
						</div>
					</div>
				</div>
				<NewConfigurationTemplates
					@subnet="args => this.newConfiguration.Address = args"
					@port="args => this.newConfiguration.ListenPort = args"
				></NewConfigurationTemplates>
				<div class="card rounded-3 shadow">
					<div class="card-header">
						<LocaleText t="Listen Port"></LocaleText>
					</div>
					<div class="card-body">
						<input type="number" class="form-control" placeholder="0-65353" id="ListenPort" 
						       min="1"
						       max="65353"
						       v-model="this.newConfiguration.ListenPort"
						       :disabled="this.loading"
						       required>
						<div class="invalid-feedback">
							<div v-if="this.error">{{this.errorMessage}}</div>
							<div v-else>
								<LocaleText t="Invalid port"></LocaleText>
							</div>
						</div>
					</div>
				</div>
				<div class="card rounded-3 shadow">
					<div class="card-header d-flex align-items-center">
						<LocaleText t="IP Address/CIDR"></LocaleText>
						<span class="badge rounded-pill text-bg-success ms-auto"><LocaleText :t="numberOfAvailableIPs + ' Available IP Address'"></LocaleText></span>
					</div>
					<div class="card-body">
						<input type="text" class="form-control" 
						       placeholder="Ex: 10.0.0.1/24" id="Address" 
						       v-model="this.newConfiguration.Address"
						       :disabled="this.loading"
						       required>
						<div class="invalid-feedback">
							<div v-if="this.error">{{this.errorMessage}}</div>
							<div v-else>
								IP Address/CIDR is invalid
							</div>
							
						</div>
					</div>
				</div>
				
				<hr>
				<div class="accordion" id="newConfigurationOptionalAccordion">
					<div class="accordion-item">
						<h2 class="accordion-header">
							<button class="accordion-button collapsed" type="button" data-bs-toggle="collapse" data-bs-target="#newConfigurationOptionalAccordionCollapse">
								<LocaleText t="Optional Settings"></LocaleText>
							</button>
						</h2>
						<div id="newConfigurationOptionalAccordionCollapse" 
						     class="accordion-collapse collapse" data-bs-parent="#newConfigurationOptionalAccordion">
							<div class="accordion-body d-flex flex-column gap-3">
								<!-- Пресет максимальной защиты от DPI -->
								<div class="card rounded-3 border-primary" v-if="this.newConfiguration.Protocol === 'awg'">
									<div class="card-header d-flex align-items-center gap-2">
										<i class="bi bi-shield-lock-fill text-primary"></i>
										<LocaleText t="DPI hardened profile"></LocaleText>
										<span class="badge rounded-pill text-bg-primary ms-auto">AWG 3.1</span>
									</div>
									<div class="card-body d-flex flex-column gap-2">
										<small class="text-muted">
											<LocaleText t="Fills in the parameters recommended by the AmneziaWG 3.1 documentation for maximum protection against DPI detection. You can adjust any value afterwards."></LocaleText>
										</small>
										<div class="form-check form-switch">
											<input class="form-check-input" type="checkbox" role="switch"
											       id="headerProtectionEnabled"
											       v-model="this.headerProtectionEnabled">
											<label class="form-check-label" for="headerProtectionEnabled">
												<LocaleText t="Enable Header Protection (sets H1-H4 to 1/2/3/4)"></LocaleText>
											</label>
										</div>
										<button class="btn btn-primary btn-sm rounded-3 align-self-start"
										        type="button"
										        :disabled="this.loading"
										        @click="this.generateDPIHardenedProfile()">
											<i class="bi bi-magic me-1"></i>
											<LocaleText t="Apply maximum DPI protection"></LocaleText>
										</button>
										<div class="alert alert-success rounded-3 py-2 px-3 mb-0" v-if="this.profileGenerated">
											<small>
												<LocaleText t="Profile applied."></LocaleText>
												<LocaleText :t="'Set peer MTU to ' + this.recommendedMTU + ' to avoid fragmentation.'"></LocaleText>
											</small>
										</div>
									</div>
								</div>

								<div class="card rounded-3" v-for="key in ['Table', 'PreUp', 'PreDown', 'PostUp', 'PostDown']">
									<div class="card-header">{{ key }}</div>
									<div class="card-body">
										<input type="text" 
										       class="form-control font-monospace" :id="key" v-model="this.newConfiguration[key]">
									</div>
								</div>

								<!-- AmneziaWG 2.0+ parameters -->
								<div class="card rounded-3"
								     v-if="this.newConfiguration.Protocol === 'awg'"
								     v-for="key in ['Jc', 'Jmin', 'Jmax', 'S1', 'S2', 'S3', 'S4', 'I1', 'I2', 'I3', 'I4', 'I5']">
									<div class="card-header">{{ key }}</div>
									<div class="card-body">
										<input type="text"
										       class="form-control font-monospace" :id="key" v-model="this.newConfiguration[key]">
										<div class="form-text" v-if="AMNEZIA_PARAM_INFO[key]">
											<LocaleText :t="AMNEZIA_PARAM_INFO[key].text"></LocaleText>
										</div>
									</div>
								</div>

								<!-- H1-H4: диапазоны не должны пересекаться -->
								<div class="card rounded-3" v-if="this.newConfiguration.Protocol === 'awg'">
									<div class="card-header d-flex align-items-center">
										H1, H2, H3, H4
										<button class="btn btn-sm btn-outline-primary ms-auto"
										        type="button" @click="this.generateHeaderValues()"
										        v-if="!this.headerProtectionEnabled">
											<i class="bi bi-arrow-repeat me-1"></i>
											<LocaleText t="Regenerate"></LocaleText>
										</button>
									</div>
									<div class="form-text mb-2">
										<LocaleText t="Message type identifiers for the four packet formats. Ranges must not overlap. Values 1/2/3/4 disable the corresponding mechanism, which is required when using Header Protection."></LocaleText>
									</div>
									<div class="card-body d-flex flex-column gap-2">
										<input type="text"
										       class="form-control font-monospace" id="H1" v-model="this.newConfiguration.H1"
										       placeholder="например, 10-1000">
										<input type="text"
										       class="form-control font-monospace" id="H2" v-model="this.newConfiguration.H2"
										       placeholder="например, 2000-3000">
										<input type="text"
										       class="form-control font-monospace" id="H3" v-model="this.newConfiguration.H3"
										       placeholder="например, 4000-5000">
										<input type="text"
										       class="form-control font-monospace" id="H4" v-model="this.newConfiguration.H4"
										       placeholder="например, 6000-7000">
										<div class="form-text">
											<LocaleText t="H1-H4 ranges must not overlap each other"></LocaleText>
										</div>
									</div>
								</div>
								
								<!-- AmneziaWG 3.1 new parameters -->
								<div class="card rounded-3" 
								     v-if="this.newConfiguration.Protocol === 'awg'">
									<div class="card-header d-flex align-items-center">
										HeaderProtectionKey
										<span class="badge rounded-pill text-bg-info ms-auto">AWG 3.1</span>
									</div>
									<div class="card-body">
										<div class="input-group">
											<input type="text"
											       class="form-control font-monospace" 
											       id="HeaderProtectionKey" 
											       v-model="this.newConfiguration.HeaderProtectionKey"
											       placeholder="64 hex characters (32 bytes)">
											<button class="btn btn-outline-primary" type="button"
											        @click="generateHeaderProtectionKey()">
												<i class="bi bi-arrow-repeat"></i>
											</button>
										</div>
										<div class="form-text">32-byte key for Header Protection (ChaCha20)</div>
										<div class="form-text" v-if="AMNEZIA_PARAM_INFO['HeaderProtectionKey']">
											<LocaleText :t="AMNEZIA_PARAM_INFO['HeaderProtectionKey'].text"></LocaleText>
										</div>
									</div>
								</div>
								
								<div class="card rounded-3" 
								     v-if="this.newConfiguration.Protocol === 'awg'"
								     v-for="key in ['ContentPaddingAddition', 'RekeyAfterTime', 'RekeyTimeout', 'RejectAfterTime', 'KeepaliveTimeout', 'MaxHandshakeAttempts']">
									<div class="card-header d-flex align-items-center">
										{{ key }}
										<span class="badge rounded-pill text-bg-info ms-auto">AWG 3.1</span>
									</div>
									<div class="card-body">
										<input type="text"
										       class="form-control font-monospace" :id="key" v-model="this.newConfiguration[key]"
										       placeholder="e.g., 10-100 or 50">
										<div class="form-text" v-if="AMNEZIA_PARAM_INFO[key]">
											<LocaleText :t="AMNEZIA_PARAM_INFO[key].text"></LocaleText>
										</div>
									</div>
								</div>
								
								<div class="card rounded-3" 
								     v-if="this.newConfiguration.Protocol === 'awg'"
								     v-for="key in ['RandomTrailers', 'DisableCookies']">
									<div class="card-header d-flex align-items-center">
										{{ key }}
										<span class="badge rounded-pill text-bg-info ms-auto">AWG 3.1</span>
									</div>
									<div class="card-body">
										<select class="form-select" :id="key" v-model="this.newConfiguration[key]">
											<option value="off">off</option>
											<option value="on">on</option>
										</select>
									</div>
								</div>
							</div>
						</div>
					</div>
				</div>
				<button class="btn btn-dark btn-brand rounded-3 px-3 py-2 shadow ms-auto"
				        :disabled="!this.goodToSubmit || this.loading || this.success">
					<span v-if="this.success" class="d-flex w-100">
						<LocaleText t="Success"></LocaleText>!
						 <i class="bi bi-check-circle-fill ms-2"></i>
					</span>
					<span v-else-if="!this.loading" class="d-flex w-100">
						<i class="bi bi-save-fill me-2"></i>
						<LocaleText t="Save"></LocaleText>
					</span>
					<span v-else class="d-flex w-100 align-items-center">
						<LocaleText t="Saving..."></LocaleText>
						<span class="ms-2 spinner-border spinner-border-sm" role="status">
						</span>
					</span>
				</button>
			</form>
		</div>
	</div>
</template>

<style scoped>
.protocolBtnGroup a{
	transition: all 0.2s ease-in-out;
}
</style>
<script setup lang="ts" async>
import {useRoute, useRouter} from "vue-router";
import { fetchGet, fetchPost } from "@/utilities/fetch.js"


import {DashboardClientAssignmentStore} from "@/stores/DashboardClientAssignmentStore.js";
import { DashboardConfigurationStore } from "@/stores/DashboardConfigurationStore.js"

import {computed, reactive, ref, watch} from "vue";
import LocaleText from "@/components/text/localeText.vue";
import ClientAssignedPeers from "@/components/clientComponents/clientAssignedPeers.vue";
import ClientResetPassword from "@/components/clientComponents/clientResetPassword.vue";
import ClientDelete from "@/components/clientComponents/clientDelete.vue";
const assignmentStore = DashboardClientAssignmentStore()
const dashboardConfigurationStore = DashboardConfigurationStore()

const route = useRoute()
const router = useRouter()
const client = computed(() => {
	return assignmentStore.getClientById(route.params.id)
})
const clientAssignedPeers = ref({})
const getAssignedPeers = async () => {
	await fetchGet('/api/clients/assignedPeers', {
		ClientID: client.value.ClientID
	}, (res) => {
		clientAssignedPeers.value = res.data;
	})
}
const emits = defineEmits(['deleteSuccess'])

const clientProfile = reactive({
	Name: undefined
})

if (client.value){
	watch(() => client.value.ClientID, async () => {
		clientProfile.Name = client.value.Name;
		loadPaymentInfo()
		await getAssignedPeers()
	})
	await getAssignedPeers()
	clientProfile.Name = client.value.Name
}else{
	router.push('/clients')
	dashboardConfigurationStore.newMessage("WGDashboard", "Client does not exist", "danger")
}



const updatingProfile = ref(false)
const updateProfile = async () => {
	updatingProfile.value = true
	await fetchPost("/api/clients/updateProfileName", {
		ClientID: client.value.ClientID,
		Name: clientProfile.Name
	}, (res) => {
		if (res.status){
			client.value.Name = clientProfile.Name;
			dashboardConfigurationStore.newMessage("Server", "Client name update success", "success")
		}else{
			clientProfile.Name = client.value.Name;
			dashboardConfigurationStore.newMessage("Server", "Client name update failed", "danger")
		}
		updatingProfile.value = false
	})
}

// --- Трекер оплат (только для администратора) ---
const payment = reactive({
	Telegram: '',
	Comment: '',
	PaidUntil: '',
	Days: 30
})
const savingPayment = ref(false)
const extendingPayment = ref(false)

const paymentStatus = computed(() => client.value?.PaymentStatus || 'unset')

const paymentBadge = computed(() => {
	switch (paymentStatus.value){
		case 'active':
			return {cls: 'text-bg-success', icon: 'bi-check-circle-fill', text: 'Paid'}
		case 'expiring':
			return {cls: 'text-bg-warning', icon: 'bi-exclamation-triangle-fill', text: 'Expiring soon'}
		case 'expired':
			return {cls: 'text-bg-danger', icon: 'bi-x-octagon-fill', text: 'Payment overdue'}
		default:
			return {cls: 'text-bg-secondary', icon: 'bi-dash-circle', text: 'No payment date set'}
	}
})

const loadPaymentInfo = () => {
	payment.Telegram = client.value?.Telegram || ''
	payment.Comment = client.value?.Comment || ''
	payment.PaidUntil = client.value?.PaidUntilFormatted || ''
}

const savePaymentInfo = async () => {
	savingPayment.value = true
	await fetchPost("/api/clients/updatePaymentInfo", {
		ClientID: client.value.ClientID,
		Telegram: payment.Telegram,
		Comment: payment.Comment,
		PaidUntil: payment.PaidUntil
	}, async (res) => {
		if (res.status){
			Object.assign(client.value, res.data)
			loadPaymentInfo()
			await assignmentStore.getClients()
			dashboardConfigurationStore.newMessage("Server", "Payment info saved", "success")
		}else{
			dashboardConfigurationStore.newMessage("Server", res.message, "danger")
		}
		savingPayment.value = false
	})
}

const extendPayment = async (days) => {
	extendingPayment.value = true
	await fetchPost("/api/clients/extendPayment", {
		ClientID: client.value.ClientID,
		Days: days
	}, async (res) => {
		if (res.status){
			Object.assign(client.value, res.data)
			loadPaymentInfo()
			await assignmentStore.getClients()
			dashboardConfigurationStore.newMessage("Server", `Extended by ${days} day(s)`, "success")
		}else{
			dashboardConfigurationStore.newMessage("Server", res.message, "danger")
		}
		extendingPayment.value = false
	})
}

const clearPaymentDate = async () => {
	payment.PaidUntil = ''
	await savePaymentInfo()
}

loadPaymentInfo()
const deleteSuccess = async () => {
	await router.push('/clients')
	await assignmentStore.getClients()
}

</script>

<template>
	<div class="text-body d-flex flex-column overflow-y-scroll h-100" v-if="client" :key="client.ClientID">
		<div class="p-4 border-bottom bg-body-tertiary z-0">
			<div class="mb-3 backLink">
				<RouterLink to="/clients" class="text-body text-decoration-none">
					<i class="bi bi-arrow-left me-2"></i>
					Back</RouterLink>
			</div>
			<small class="text-muted">
				<LocaleText t="Email"></LocaleText>
			</small>
			<h1>
				{{ client.Email }}
			</h1>
			<div class="d-flex flex-column gap-2">
				<div class="d-flex align-items-center">
					<small class="text-muted">
						<LocaleText t="Client ID"></LocaleText>
					</small>
					<small class="ms-auto">
						<samp>{{ client.ClientID }}</samp>
					</small>
				</div>
				<div class="d-flex align-items-center gap-2">
					<small class="text-muted">
						<LocaleText t="Client Name"></LocaleText>
					</small>
					<input class="form-control form-control-sm rounded-3 ms-auto"
						   style="width: 300px"
						   type="text" v-model="clientProfile.Name">
					<button
						@click="updateProfile()"
						aria-label="Save Client Name"
						class="btn btn-sm rounded-3 bg-success-subtle border-success-subtle text-success-emphasis">
						<i class="bi bi-save-fill"></i>
					</button>
				</div>
			</div>
		</div>
		<!-- Трекер оплат: только для администратора, трафик не отключается -->
		<div class="p-4 border-bottom" v-if="client">
			<div class="d-flex align-items-center gap-2 mb-3">
				<i class="bi bi-cash-coin text-muted"></i>
				<strong class="small">
					<LocaleText t="Payment"></LocaleText>
				</strong>
				<span class="badge rounded-pill ms-auto" :class="paymentBadge.cls">
					<i class="bi me-1" :class="paymentBadge.icon"></i>
					{{ paymentBadge.text }}
				</span>
			</div>

			<div class="row g-2">
				<div class="col-sm-4">
					<label class="form-label">
						<small class="text-muted">
							<LocaleText t="Telegram"></LocaleText>
						</small>
					</label>
					<input type="text" class="form-control form-control-sm rounded-3"
					       v-model="payment.Telegram" placeholder="@username">
				</div>
				<div class="col-sm-4">
					<label class="form-label">
						<small class="text-muted">
							<LocaleText t="Paid Until"></LocaleText>
						</small>
					</label>
					<input type="date" class="form-control form-control-sm rounded-3"
					       v-model="payment.PaidUntil">
					<div class="form-text" v-if="client.DaysRemaining !== null && client.DaysRemaining !== undefined">
						<LocaleText v-if="client.DaysRemaining < 0"
						            :t="'Overdue by ' + Math.abs(client.DaysRemaining) + ' day(s)'"></LocaleText>
						<LocaleText v-else
						            :t="client.DaysRemaining + ' day(s) left'"></LocaleText>
					</div>
				</div>
				<div class="col-sm-4">
					<label class="form-label">
						<small class="text-muted">
							<LocaleText t="Extend by"></LocaleText>
						</small>
					</label>
					<div class="input-group input-group-sm">
						<input type="number" min="1" max="3650"
						       class="form-control rounded-3"
						       v-model.number="payment.Days">
						<button class="btn btn-outline-primary"
						        :disabled="extendingPayment"
						        @click="extendPayment(payment.Days)">
							<LocaleText t="Extend"></LocaleText>
						</button>
					</div>
				</div>
				<div class="col-12">
					<label class="form-label">
						<small class="text-muted">
							<LocaleText t="Comment"></LocaleText>
						</small>
					</label>
					<textarea class="form-control form-control-sm rounded-3" rows="2"
					          v-model="payment.Comment"
					          placeholder="Payment notes, method, anything for your own reference"></textarea>
				</div>
			</div>

			<div class="d-flex align-items-center gap-2 mt-3">
				<small class="text-muted fst-italic">
					<LocaleText t="Payment status is only visible to the administrator. The client is never notified and access is not restricted."></LocaleText>
				</small>
				<button class="btn btn-sm rounded-3 bg-primary-subtle border-primary-subtle text-primary-emphasis ms-auto"
				        :disabled="savingPayment"
				        @click="savePaymentInfo()">
					<i class="bi bi-save-fill me-1"></i>
					<LocaleText t="Save"></LocaleText>
				</button>
				<button class="btn btn-sm rounded-3 bg-secondary-subtle border-secondary-subtle text-secondary-emphasis"
				        v-if="client.PaidUntilFormatted"
				        :disabled="savingPayment"
				        @click="clearPaymentDate()">
					<LocaleText t="Clear date"></LocaleText>
				</button>
			</div>
		</div>
		<div style="flex: 1 0 0; overflow-y: scroll;">
			<ClientAssignedPeers
				@refresh="getAssignedPeers()"
				:clientAssignedPeers="clientAssignedPeers"
				:client="client"></ClientAssignedPeers>
<!--			<ClientResetPassword-->
<!--				:client="client" v-if="client.ClientGroup === 'Local'"></ClientResetPassword>-->
			<ClientDelete
				@deleteSuccess="deleteSuccess()"
				:client="client"></ClientDelete>
		</div>
	</div>
	<div v-else class="d-flex w-100 h-100 text-muted">
		<div class="m-auto text-center">
			<h1>
				<i class="bi bi-person-x"></i>
			</h1>
			<p>
				<LocaleText t="Client does not exist"></LocaleText>
			</p>
		</div>
	</div>
</template>

<style scoped>
@media screen and (min-width: 576px) {
	.backLink{
		display: none;
	}
}
</style>
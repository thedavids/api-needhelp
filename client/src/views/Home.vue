<script setup>
import { useAuth } from '../composables/useAuth'
import AuthButtons from '../components/AuthButtons.vue'
import UserPanel from '../components/UserPanel.vue'

const { user } = useAuth()
</script>

<template>
    <h1>I Want to Help</h1>
    <p>Be someone’s neighbor in the truest sense. Offer your time, tools, or skills to people nearby — for anything from
        errands to conversation.</p>
    <p>We're building a platform to make helping easy and local.</p>
    <UserPanel />
    <AuthButtons v-if="!user" />
</template>

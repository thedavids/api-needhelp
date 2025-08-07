<template>
    <form class="user-login-form" @submit.prevent="resetPassword">
        <h3>Reset Password</h3>
        <input v-model="password" type="password" placeholder="New password" maxlength="100" required />
        <input v-model="confirmPassword" type="password" placeholder="Confirm password" maxlength="100" required />
        <button type="submit">Reset</button>
        <p v-if="message">{{ message }}</p>
    </form>
</template>

<script setup>
import { ref } from 'vue';
import { useRoute, useRouter } from 'vue-router';

const password = ref('');
const confirmPassword = ref('');
const message = ref('');
const route = useRoute();
const router = useRouter();
const token = route.query.token;
const API_URL = import.meta.env.VITE_API_URL;

async function resetPassword() {
    if (password.value !== confirmPassword.value) {
        message.value = "Passwords don't match.";
        return;
    }

    const res = await fetch(`${API_URL}/reset-password`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify({ token, password: password.value })
    });

    const data = await res.json();
    if (res.ok) {
        message.value = 'Password reset successful. Redirecting...';
        setTimeout(() => router.push('/login'), 2000);
    }
    else {
        message.value = data.error || 'Reset failed.';
    }
}
</script>

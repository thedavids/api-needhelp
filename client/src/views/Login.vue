<template>
    <form class="user-login-form" @submit.prevent="login">
        <h3>{{ $t('login') }}</h3>
        <input v-model="email" type="email" :placeholder="$t('email')" maxlength="254" required />
        <input v-model="password" type="password" :placeholder="$t('password')" maxlength="100" required />
        <button type="submit">{{ $t('login') }}</button>

        <p class="forgot-password">
            <router-link to="/forgot-password">{{ $t('forgot_password') }}</router-link>
        </p>
    </form>
    <AuthButtons />
</template>

<script setup>
import { ref } from 'vue';
import { useRouter } from 'vue-router';
import AuthButtons from '../components/AuthButtons.vue';

const API_URL = import.meta.env.VITE_API_URL;
const email = ref('');
const password = ref('');
const router = useRouter();

async function login() {
    const res = await fetch(`${API_URL}/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify({ email: email.value, password: password.value })
    });

    if (res.ok) {
        router.push('/');
    }
    else {
        const data = await res.json();
        alert(data.error || 'Login failed');
    }
}
</script>

<template>
    <form class="user-login-form" @submit.prevent="sendReset">
        <h3>Forgot Password</h3>
        <input v-model="email" type="email" placeholder="Enter your email" required />
        <button type="submit" :disabled="loading">
            {{ loading ? 'Sending Reset Link...' : 'Send Reset Link' }}
        </button>
        <p v-if="message">{{ message }}</p>
    </form>
</template>

<script setup>
import { ref } from 'vue';
import { useRouter } from 'vue-router';

const email = ref('');
const message = ref('');
const loading = ref(false);
const router = useRouter();
const API_URL = import.meta.env.VITE_API_URL;

async function sendReset() {

    loading.value = true;
    try {
        const res = await fetch(`${API_URL}/forgot-password`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            credentials: 'include',
            body: JSON.stringify({ email: email.value })
        });

        if (res.status === 201) {
            const data = await res.json();
            alert(data.message || 'If your email is valid, a reset link was sent.');
            router.push('/login');
        }
        else {
            const error = await res.json();
            alert(error.error || 'Forgot password failed!');
        }
    }
    catch (err) {
        console.log(err);
        alert('Forgot password failed!');
    }
    finally {
        loading.value = false;
    }
}
</script>

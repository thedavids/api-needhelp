<template>
    <form class="user-login-form" @submit.prevent="register">
        <h3>Sign Up</h3>
        <input v-model="email" type="email" placeholder="Email" maxlength="254" required />
        <input v-model="displayName" placeholder="Display Name" maxlength="254" required />
        <input v-model="password" type="password" placeholder="Password" maxlength="100" required />
        <input v-model="confirmPassword" type="password" placeholder="Confirm Password" maxlength="100" required />
        <button type="submit" :disabled="loading">
            {{ loading ? 'Registering...' : 'Register' }}
        </button>
    </form>
    <AuthButtons />
</template>

<style></style>

<script setup>
import { ref } from 'vue';
import { useRouter } from 'vue-router';
import AuthButtons from '../components/AuthButtons.vue';

const email = ref('');
const displayName = ref('');
const password = ref('');
const confirmPassword = ref('');
const loading = ref(false);
const router = useRouter();

async function register() {
    if (password.value !== confirmPassword.value) {
        alert("Passwords do not match");
        return;
    }

    loading.value = true;
    try {
        const res = await fetch(`${import.meta.env.VITE_API_URL}/register`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            credentials: 'include',
            body: JSON.stringify({
                email: email.value,
                displayName: displayName.value,
                password: password.value
            })
        });

        if (res.status === 201) {
            const data = await res.json();
            alert(data.message || 'Registration successful! Please check your email to verify your account.');
            router.push('/');
        }
        else {
            const error = await res.json();
            alert(error.error || 'Registration failed');
        }
    }
    catch(err) {
        console.log(err);
        alert('Registration failed');
    }
    finally {
        loading.value = false;
    }
}
</script>

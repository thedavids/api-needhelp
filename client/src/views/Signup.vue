<template>
    <form class="user-login-form" @submit.prevent="register">
        <h3>Sign Up</h3>
        <input v-model="email" type="email" placeholder="Email" required />
        <input v-model="displayName" placeholder="Display Name" required />
        <input v-model="password" type="password" placeholder="Password" required />
        <input v-model="confirmPassword" type="password" placeholder="Confirm Password" required />
        <button type="submit">Register</button>
    </form>
</template>

<style></style>

<script setup>
import { ref } from 'vue';
import { useRouter } from 'vue-router';

const email = ref('');
const displayName = ref('');
const password = ref('');
const confirmPassword = ref('');
const router = useRouter();

async function register() {
    if (password.value !== confirmPassword.value) {
        alert("Passwords do not match");
        return;
    }

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
}
</script>

<template>
  <div>
    <router-link to="/login"><button>Login</button></router-link>
    <router-link to="/signup"><button>Sign up</button></router-link>
    <a :href="`${API_URL}/auth/google`" class="login-with-google-btn">Login with Google</a>
    <a :href="`${API_URL}/auth/facebook`" class="login-with-facebook-btn">Login with Facebook</a>
  </div>
</template>

<script setup>
const API_URL = import.meta.env.VITE_API_URL
</script>

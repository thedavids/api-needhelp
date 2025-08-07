<template>
  <div v-if="user">
    <p>Logged in as {{ user.displayName }}</p>
    <button @click="logout">Logout</button>
  </div>
</template>

<style scoped>
div {
    text-align: center;
}
</style>

<script setup>
import { onMounted } from 'vue'
import { useAuth } from '../composables/useAuth'
const API_URL = import.meta.env.VITE_API_URL

const { user, setUser, clearUser } = useAuth()

async function fetchUser() {
  const res = await fetch(`${API_URL}/me`, { credentials: 'include' })
  if (res.ok) {
    const data = await res.json()
    setUser(data.user)
  }
}

async function logout() {
  await fetch(`${API_URL}/logout`, {
    method: 'POST',
    credentials: 'include'
  })
  clearUser()
}

onMounted(fetchUser)
</script>

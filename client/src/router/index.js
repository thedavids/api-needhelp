import { createRouter, createWebHistory } from 'vue-router';
import Home from '../views/Home.vue';
import Login from '../views/Login.vue';
import Signup from '../views/Signup.vue';
import VerifyEmail from '../views/VerifyEmail.vue';

const routes = [
    { path: '/', component: Home },
    { path: '/login', component: Login },
    { path: '/signup', component: Signup },
    { path: '/verify', component: VerifyEmail },
    { path: '/index.html', redirect: '/' }
];

export const router = createRouter({
    history: createWebHistory(),
    routes
});
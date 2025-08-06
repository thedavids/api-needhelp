import './style.css';

const API_URL = import.meta.env.VITE_API_URL;

const loginForm = document.getElementById('login-form');
const registerForm = document.getElementById('register-form');
const showLoginBtn = document.getElementById('show-login');
const showRegisterBtn = document.getElementById('show-register');
const logoutBtn = document.getElementById('logout');
const authForms = document.getElementById('auth-forms');
const authButtons = document.getElementById('auth-buttons');
const userPanel = document.getElementById('user-panel');
const userInfo = document.getElementById('user-info');

const googleAuthUrl = `${API_URL}/auth/google?prompt=select_account`;
['google-login', 'google-signup'].forEach(id => {
    document.getElementById(id).href = googleAuthUrl;
});

// Show forms
showLoginBtn.onclick = () => {
    loginForm.style.display = 'block';
    registerForm.style.display = 'none';
    authForms.style.display = 'block';
};

showRegisterBtn.onclick = () => {
    loginForm.style.display = 'none';
    registerForm.style.display = 'block';
    authForms.style.display = 'block';
};

// Login
loginForm.onsubmit = async (e) => {
    e.preventDefault();
    const formData = new FormData(loginForm);
    const body = {
        username: formData.get('username'),
        password: formData.get('password')
    };

    const res = await fetch(`${API_URL}/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify(body)
    });

    if (res.ok) {
        await checkAuth();
    } else {
        alert('Login failed');
    }
};

// Register
registerForm.onsubmit = async (e) => {
    e.preventDefault();
    const formData = new FormData(registerForm);
    const body = {
        username: formData.get('username'),
        password: formData.get('password')
    };

    const res = await fetch(`${API_URL}/register`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify(body)
    });

    if (res.ok) {
        await checkAuth();
    } else {
        alert('Registration failed');
    }
};

// Logout
logoutBtn.onclick = async () => {
    await fetch(`${API_URL}/logout`, {
        method: 'POST',
        credentials: 'include'
    });
    renderLoggedOut();
};

// Check auth status
async function checkAuth() {
    const res = await fetch(`${API_URL}/me`, {
        credentials: 'include'
    });

    if (res.ok) {
        const { user } = await res.json();
        renderLoggedIn(user);
    } else {
        renderLoggedOut();
    }
}

function renderLoggedIn(user) {
    authButtons.style.display = 'none';
    authForms.style.display = 'none';
    userPanel.style.display = 'block';
    userInfo.textContent = `Logged in as ${user.username}`;
}

function renderLoggedOut() {
    authButtons.style.display = 'block';
    authForms.style.display = 'none';
    userPanel.style.display = 'none';
}

checkAuth(); // Run on page load
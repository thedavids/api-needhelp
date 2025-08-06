document.getElementById('login-form').addEventListener('submit', handleLogin);

export async function handleLogin(e) {
    e.preventDefault();

    const username = e.target.username.value;
    const password = e.target.password.value;

    const res = await fetch(`${import.meta.env.VITE_API_URL}/login`, {
        method: "POST",
        headers: {
            "Content-Type": "application/json"
        },
        credentials: "include", // store session cookie!
        body: JSON.stringify({ username, password })
    });

    if (res.ok) {
        const data = await res.json();
        alert(`Welcome, ${data.user.username}!`);
    } else {
        alert("Login failed");
    }
}

// Dummy users
const users = [{ id: 1, username: 'test', password: 'pass123' }];

export async function getUserByUsername(username) {
    return users.find(u => u.username === username);
}

export async function createUser(username, hashedPassword) {
    const newUser = { id: users.length + 1, username, hashedPassword };
    users.push(newUser);
    return newUser;
}

export async function getUserByGoogleId(googleId) {
    return users.find(u => u.googleId === googleId);
}

export async function createUserFromGoogleProfile(profile) {
    const newUser = {
        id: users.length + 1,
        username: profile.displayName,
        googleId: profile.id,
        email: profile.emails?.[0]?.value || null
    };
    users.push(newUser);
    return newUser;
}

export async function getUserByFacebookId(facebookId) {
    return users.find(u => u.facebookId === facebookId);
}

export async function createUserFromFacebook({ facebookId, email }) {
    const newUser = {
        id: users.length + 1,
        username: `fb_user_${facebookId.slice(-6)}`,
        facebookId,
        email: email || null,
        googleId: null,
        password: null // no password for Facebook users
    };
    users.push(newUser);
    return newUser;
}
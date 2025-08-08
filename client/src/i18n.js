// i18n.js
import { createI18n } from 'vue-i18n';

const messages = {
    en: {
        welcome: 'Welcome',
        email: 'Email',
        email_verification: 'Email Verification',
        enter_email: 'Enter your email',
        password: 'Password',
        password_new: 'New password',
        password_confirm: 'Confirm password',
        password_reset: 'Reset Password',
        forgot_password: 'Forgot your password?',
        login: 'Login',
        login_google: 'Login with Google',
        login_facebook: 'Login with Facebook',
        display_name: 'Display Name',
        signup: 'Sign Up',
        register: 'Register',
        registering: 'Registering...',
        send_reset_link: 'Send Reset Link',
        sending_reset_link: 'Sending Reset Link...',
        logout: 'Logout',
        reset: 'Reset',
        profile: 'Profile',
        english: 'English',
        french: 'French',
        product_title: 'I Want to Help',
        product_description1: 'Be someone\'s neighbor in the truest sense. Offer your time, tools, or skills to people nearby — for anything from errands to conversation.',
        product_description2: 'We\'re building a platform to make helping easy and local.'
    },
    fr: {
        welcome: 'Bienvenue',
        email: 'Courriel',
        email_verification: 'Vérification Courriel',
        enter_email: 'Entrez votre courriel',
        password: 'Mot de passe',
        password_new: 'Nouveau mot de passe',
        password_confirm: 'Confirmation mot de passe',
        password_reset: 'Réinitialiser le Mot de passe',
        forgot_password: 'Mot de passe oublié ?',
        login: 'Connexion',
        login_google: 'Connexion Google',
        login_facebook: 'Connexion Facebook',
        display_name: 'Nom d\'affichage',
        signup: 'Inscription',
        register: 'Enregistrer',
        registering: 'Enregistrement ...',
        send_reset_link: 'Envoyer le lien',
        sending_reset_link: 'Envoie du lien ...',
        logout: 'Déconnexion',
        reset: 'Réinitialiser',
        profile: 'Profil',
        english: 'Anglais',
        french: 'Français',
        product_title: "Je veux aider",
        product_description1: "Soyez un véritable voisin. Offrez votre temps, vos outils ou vos compétences aux personnes proches de chez vous — pour tout, des courses à une simple conversation.",
        product_description2: "Nous construisons une plateforme pour rendre l'entraide facile et locale.",
    },
};

export const i18n = createI18n({
    legacy: false, // use Composition API mode
    locale: 'en', // default language
    fallbackLocale: 'en',
    messages,
});

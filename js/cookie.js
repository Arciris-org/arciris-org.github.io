function setLangCookie(lang) {
    document.cookie = `lang=${lang};path=/;expires=Fri, 31 Dec 9999 23:59:59 GMT`;
}

function getLangCookie() {
    const match = document.cookie.match(/(?:^|; )lang=([^;]*)/);
    return match ? decodeURIComponent(match[1]) : null;
}

function isCookieAgreed() {
    return localStorage.getItem('arciris_cookie_agree') === '1';
}

function setCookieAgreed() {
    localStorage.setItem('arciris_cookie_agree', '1');
}

function showCookiePopup() {
    const popup = document.getElementById('cookie-popup');
    if (popup) popup.style.display = 'flex';
}

function hideCookiePopup() {
    const popup = document.getElementById('cookie-popup');
    if (popup) popup.style.display = 'none';
}
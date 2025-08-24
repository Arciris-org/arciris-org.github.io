function setLangCookie(lang) {
    document.cookie = `lang=${lang};path=/;expires=Fri, 31 Dec 9999 23:59:59 GMT`;
}

function getLangCookie() {
    const match = document.cookie.match(/(?:^|; )lang=([^;]*)/);
    return match ? decodeURIComponent(match[1]) : null;
}
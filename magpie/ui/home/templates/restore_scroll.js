document.addEventListener("DOMContentLoaded", function (event) {
    let pos = sessionStorage.getItem('scroll-position');
    if (pos) {
        window.scrollTo(0, pos);
        sessionStorage.removeItem('scroll-position');
    }
});

window.addEventListener("beforeunload", function (e) {
    sessionStorage.setItem('scroll-position', window.scrollY);
});

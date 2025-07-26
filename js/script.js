
document.addEventListener('DOMContentLoaded', function() {
    const bgDiv = document.querySelector('.min-h-screen.bg-gradient-to-br');
    if (bgDiv) {
        let t = 0;
        function animateGradient() {
            t += 0.025;
            const color1 = '#fff';
            const color2 = '#f1f5f9';
            const color3 = '#c2ceddff';
            const p1 = 5 + Math.sin(t) * 45;
            const p2 = 50 + Math.cos(t/2) * 45;
            const p3 = 100;
            bgDiv.style.background = `linear-gradient(135deg, ${color1} ${p1}%, ${color2} ${p2}%, ${color3} ${p3}%)`;
            requestAnimationFrame(animateGradient);
        }
        animateGradient();
    }

    const btn = document.getElementById('start-btn');
    if (btn) {
        btn.addEventListener('click', function(e) {
            e.preventDefault();
            btn.classList.add('opacity-0', 'pointer-events-none', 'transition-all', 'duration-500');
            setTimeout(() => {
                const main = btn.closest('main');
                if (main) {
                    main.innerHTML = `<div class="flex flex-col items-center justify-center h-96"><h2 class=\"text-4xl font-bold text-blue-700 mb-4\">ようこそArcirisへ</h2><p class=\"text-lg text-blue-900/80\">新しい体験をお楽しみください。</p></div>`;
                }
            }, 600);
        });
    }
});

document.addEventListener('DOMContentLoaded', function() {
    const menuBtn = document.getElementById('menu-btn');
    const mainNav = document.getElementById('main-nav');
    if (menuBtn && mainNav) {
        menuBtn.addEventListener('click', function() {
            mainNav.classList.toggle('hidden');
        });
        window.addEventListener('resize', function() {
            if (window.innerWidth >= 768) {
                mainNav.classList.add('hidden');
            }
        });
        document.addEventListener('click', function(e) {
            if (
                !mainNav.classList.contains('hidden') &&
                !mainNav.contains(e.target) &&
                !menuBtn.contains(e.target)
            ) {
                mainNav.classList.add('hidden');
            }
        });
        const navLinks = document.querySelectorAll('#main-nav a[href^="#"]');
        navLinks.forEach(link => {
            link.addEventListener('click', function(e) {
                const href = link.getAttribute('href');
                const targetId = href.split('#')[1];
                if (targetId) {
                    const target = document.getElementById(targetId);
                    if (target) {
                        e.preventDefault();
                        target.scrollIntoView({ behavior: 'smooth' });
                        if (window.innerWidth < 768 && mainNav) {
                            mainNav.classList.add('hidden');
                        }
                    }
                }
            });
        });
    }
    const bgDiv = document.querySelector('.min-h-screen.bg-gradient-to-br');
    if (bgDiv) {
        let t = 0;
        function animateGradient() {
            t += 0.018;
            const color1 = `rgba(${230 + Math.sin(t)*15},${240 + Math.cos(t)*10},255,1)`;
            const color2 = `rgba(180,210,255,${0.7 + 0.2*Math.sin(t/2)})`;
            const color3 = `rgba(120,180,255,${0.5 + 0.3*Math.cos(t/3)})`;
            const color4 = `rgba(200,255,255,${0.6 + 0.2*Math.sin(t/1.5)})`;
            const color5 = `rgba(255,255,255,${0.8 + 0.1*Math.cos(t/4)})`;
            const angle = 120 + Math.sin(t/2)*30;
            const p1 = 5 + Math.sin(t) * 30;
            const p2 = 30 + Math.cos(t/2) * 30;
            const p3 = 60 + Math.sin(t/3) * 30;
            const p4 = 85 + Math.cos(t/1.5) * 10;
            const p5 = 100;
            bgDiv.style.background = `linear-gradient(${angle}deg, ${color1} ${p1}%, ${color2} ${p2}%, ${color3} ${p3}%, ${color4} ${p4}%, ${color5} ${p5}%)`;
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

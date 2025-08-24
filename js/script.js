document.addEventListener('DOMContentLoaded', function() {
    window.setLanguage = function(lang) {
        const jsonFile = lang === 'en' ? 'i18n/template.json' : `i18n/${lang}.json`;
        fetch(jsonFile)
            .then(res => res.json())
            .then(data => {
                const elements = [
                    { selector: '#main-nav a', prop: 'textContent', keys: ['features', 'about', 'download'] },
                    { selector: 'h1', prop: 'innerHTML', key: 'title' },
                    { selector: 'a[href="#download"]', prop: 'textContent', key: 'download' },
                    { selector: 'a[href="#features"]', prop: 'textContent', key: 'learn_more' },
                    { selector: '#features h2', prop: 'textContent', key: 'features' },
                    { selector: '#download h2', prop: 'textContent', key: 'footer_download' },
                    { selector: '#download a', prop: 'textContent', key: 'footer_download_btn' }
                ];
                elements.forEach(item => {
                    if (item.keys) {
                        const nodes = document.querySelectorAll(item.selector);
                        item.keys.forEach((key, i) => {
                            if (nodes[i]) nodes[i][item.prop] = data[key];
                        });
                    } else {
                        const el = document.querySelector(item.selector);
                        if (el && data[item.key]) el[item.prop] = data[item.key];
                    }
                });

                const features = [
                    {
                        title: 'custom_init_system',
                        desc: 'custom_init_system_desc',
                        titleSelector: '#features .grid > div:nth-child(1) h3',
                        descSelector: '#features .grid > div:nth-child(1) p'
                    },
                    {
                        title: 'async_pkg_verfication',
                        desc: 'async_pkg_verfication_desc',
                        titleSelector: '#features .grid > div:nth-child(2) h3',
                        descSelector: '#features .grid > div:nth-child(2) p'
                    },
                    {
                        title: 'secure_by_desgin',
                        desc: 'secure_by_desgin_desc',
                        titleSelector: '#features .grid > div:nth-child(3) h3',
                        descSelector: '#features .grid > div:nth-child(3) p'
                    }
                ];
                features.forEach(f => {
                    const titleEl = document.querySelector(f.titleSelector);
                    if (titleEl && data[f.title]) titleEl.textContent = data[f.title];
                    const descEl = document.querySelector(f.descSelector);
                    if (descEl && data[f.desc]) descEl.innerHTML = data[f.desc];
                });

                const downloadPageTitle = document.getElementById('download-page-title');
                if (downloadPageTitle && data.download_page_title) downloadPageTitle.textContent = data.download_page_title;
                const downloadPageDesc = document.getElementById('download-page-desc');
                if (downloadPageDesc && data.download_page_desc) downloadPageDesc.innerHTML = data.download_page_desc.replace(/\n/g, '<br>');
                const downloadPageGithub = document.getElementById('download-page-github');
                if (downloadPageGithub && data.download_page_github) downloadPageGithub.textContent = data.download_page_github;
                const downloadPageFooter = document.getElementById('download-page-footer');
                if (downloadPageFooter && data.footer_download_txt) downloadPageFooter.textContent = data.footer_download_txt;
            });
    }
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
    }
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
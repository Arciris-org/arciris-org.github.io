document.addEventListener('DOMContentLoaded', function() {
    window.setLanguage = function(lang) {
        const jsonFile = lang === 'en' ? 'i18n/template.json' : `i18n/${lang}.json`;
        fetch(jsonFile)
            .then(res => {
                if (!res.ok) {
                    throw new Error(`Failed to get laungage file: ${jsonFile}`);
                }
                return res.json();
            })
            .then(data => {
                const elements = [
                    { selector: '#main-nav a', prop: 'textContent', keys: ['features', 'about', 'download'] },
                    { selector: 'h1', prop: 'innerHTML', key: 'title' },
                    { selector: 'a[href="#download"]', prop: 'textContent', key: 'download' },
                    { selector: 'a[href="#features"]', prop: 'textContent', key: 'learn_more' },
                    { selector: '#features h2', prop: 'textContent', key: 'features' },
                    { selector: '#download h2', prop: 'textContent', key: 'footer_download' },
                    { selector: '#download a', prop: 'textContent', key: 'footer_download_btn' },
                    { selector: '#about h2', prop: 'textContent', key: 'about' },
                    // 1つ目のabout説明文
                    { selector: '#about p', prop: 'innerHTML', key: 'about_desc' },
                    { selector: '#about ul', prop: 'innerHTML', keys: ['about_list_1', 'about_list_2', 'about_list_3', 'about_list_4', 'about_list_5'] },
                    // 2つ目のabout説明文（.mt-6付きpタグ）
                    { selector: '#about p.mt-6', prop: 'innerHTML', key: 'about_desc_2' }
                ];
                elements.forEach(item => {
                    if (item.keys) {
                        const nodes = document.querySelectorAll(item.selector);
                        if (item.selector === '#about ul') {
                            let html = '';
                            item.keys.forEach(key => {
                                if (data[key]) html += `<li>${data[key]}</li>`;
                            });
                            if (nodes[0]) nodes[0].innerHTML = html;
                        } else {
                            item.keys.forEach((key, i) => {
                                if (nodes[i] && data[key]) nodes[i][item.prop] = data[key];
                            });
                        }
                    } else {
                        if (item.selector === '#about p.mt-6') {
                            const el = document.querySelector('#about p.mt-6');
                            if (el && data[item.key]) el[item.prop] = data[item.key];
                        } else {
                            const el = document.querySelector(item.selector);
                            if (el && data[item.key]) el[item.prop] = data[item.key];
                        }
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
            })
            .catch(err => {
                console.error('setLanguage error:', err);
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
        document.addEventListener('click', function(e) {
            if (
                !mainNav.classList.contains('hidden') &&
                !mainNav.contains(e.target) &&
                !menuBtn.contains(e.target)
            ) {
                mainNav.classList.add('hidden');
            }
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
    
    const langSwitch = document.getElementById('lang-switch');
    if (langSwitch && typeof getLangCookie === 'function') {
        const prevLang = getLangCookie();
        if (prevLang) {
            langSwitch.value = prevLang;
            setLanguage(prevLang);
        } else {
            setLanguage(langSwitch.value);
        }
        langSwitch.addEventListener('change', function(e) {
            if (typeof setLangCookie === 'function') setLangCookie(e.target.value);
            setLanguage(e.target.value);
        });
    }
});
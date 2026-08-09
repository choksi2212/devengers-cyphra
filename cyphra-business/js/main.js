// CYPHRA Business Website — Main JavaScript
// Navigation, Scroll Animations, Mobile Menu

document.addEventListener('DOMContentLoaded', () => {
    // Mobile hamburger menu toggle
    const hamburger = document.querySelector('.hamburger');
    const navMenu = document.querySelector('.nav-menu');

    if (hamburger && navMenu) {
        hamburger.addEventListener('click', () => {
            navMenu.classList.toggle('active');
            hamburger.classList.toggle('active');
        });

        // Close menu on link click
        navMenu.querySelectorAll('a').forEach(link => {
            link.addEventListener('click', () => {
                navMenu.classList.remove('active');
                hamburger.classList.remove('active');
            });
        });
    }

    // Smooth scroll for anchor links
    document.querySelectorAll('a[href^="#"]').forEach(anchor => {
        anchor.addEventListener('click', function (e) {
            e.preventDefault();
            const target = document.querySelector(this.getAttribute('href'));
            if (target) {
                target.scrollIntoView({ behavior: 'smooth', block: 'start' });
            }
        });
    });

    // Scroll-based animations using IntersectionObserver
    const observerOptions = {
        threshold: 0.1,
        rootMargin: '0px 0px -50px 0px'
    };

    const observer = new IntersectionObserver((entries) => {
        entries.forEach(entry => {
            if (entry.isIntersecting) {
                entry.target.classList.add('animate-in');
                observer.unobserve(entry.target);
            }
        });
    }, observerOptions);

    // Observe elements for animation
    const animateElements = document.querySelectorAll(
        '.summary-card, .feature-card, .nav-card, .metric-card, .info-card, .chart-container, .timeline-item, .stat-card, .highlight-box, .table-responsive'
    );
    animateElements.forEach(el => {
        el.style.opacity = '0';
        el.style.transform = 'translateY(30px)';
        observer.observe(el);
    });

    // Navbar scroll effect
    const navbar = document.querySelector('.navbar');
    if (navbar) {
        window.addEventListener('scroll', () => {
            if (window.scrollY > 50) {
                navbar.style.borderBottom = '1px solid rgba(0, 255, 136, 0.15)';
                navbar.style.background = 'rgba(6, 10, 16, 0.97)';
            } else {
                navbar.style.borderBottom = '1px solid #1a2a3a';
                navbar.style.background = 'rgba(6, 10, 16, 0.92)';
            }
        });
    }

    // Counter animation for stat values
    const counters = document.querySelectorAll('.stat-value[data-target]');
    const counterObserver = new IntersectionObserver((entries) => {
        entries.forEach(entry => {
            if (entry.isIntersecting) {
                const target = parseFloat(entry.target.getAttribute('data-target'));
                const suffix = entry.target.getAttribute('data-suffix') || '';
                const prefix = entry.target.getAttribute('data-prefix') || '';
                const duration = 1500;
                const start = 0;
                const startTime = performance.now();

                function updateCounter(currentTime) {
                    const elapsed = currentTime - startTime;
                    const progress = Math.min(elapsed / duration, 1);
                    const eased = 1 - Math.pow(1 - progress, 3);
                    const current = start + (target - start) * eased;

                    if (Number.isInteger(target)) {
                        entry.target.textContent = prefix + Math.round(current).toLocaleString('en-IN') + suffix;
                    } else {
                        entry.target.textContent = prefix + current.toFixed(1) + suffix;
                    }

                    if (progress < 1) {
                        requestAnimationFrame(updateCounter);
                    }
                }
                requestAnimationFrame(updateCounter);
                counterObserver.unobserve(entry.target);
            }
        });
    }, { threshold: 0.5 });

    counters.forEach(counter => counterObserver.observe(counter));
});

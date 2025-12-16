/**
 * History API-based SPA router for Seed Card Generator
 * Maps routes to original anchor behavior:
 * / - default page
 * /generator - generator page 
 * /config/seed, /config/domain, /tokens, /examples - anchors within generator
 */

class Router {
    constructor() {
        this.routes = new Map();
        this.currentRoute = null;
        this.defaultRoute = '/';
        
        // Initialize router
        this.init();
    }
    
    init() {
        // Listen for popstate (back/forward)
        window.addEventListener('popstate', (e) => this.handleRouteChange());
        
        // Handle initial load
        window.addEventListener('load', () => this.handleRouteChange());
        
        // Listen for scroll events to update navigation based on visible section
        window.addEventListener('scroll', () => this.handleScroll());
        
        // Intercept all navigation links
        this.interceptLinks();
    }
    
    // Intercept navigation links to use history API
    interceptLinks() {
        document.addEventListener('click', (e) => {
            const link = e.target.closest('a');
            if (!link) return;
            
            const href = link.getAttribute('href');
            const dataRoute = link.getAttribute('data-route');
            
            
            // If link has data-route, let SeedCardApp handle it
            if (dataRoute) {
                return; // Don't prevent default, let SeedCardApp's handler take over
            }
            
            if (!href) return;
            
            
            // Handle SPA routes (starting with /)
            if ((href.startsWith('/') || href.startsWith('#/')) && !link.hasAttribute('target')) {
                e.preventDefault();
                let path = href;
                
                // Convert hash links to clean paths
                if (path.startsWith('#/')) {
                    path = path.slice(1);
                }
                
                this.navigate(path);
            }
            // Handle anchor links within the same page (like #security, #demo)
            else if (href.startsWith('#') && !href.startsWith('#/')) {
                e.preventDefault();
                const targetId = href.slice(1);
                this.scrollToAnchor(targetId);
            }
        });
    }
    
    // Scroll to an anchor within the current page
    scrollToAnchor(anchorId) {
        const element = document.getElementById(anchorId);
        if (element) {
            // Calculate navbar height for offset
            const navbar = document.querySelector('.generator-header');
            const navbarHeight = navbar ? navbar.offsetHeight : 80;
            
            // Get element position and account for navbar
            const elementTop = element.offsetTop - navbarHeight - 20; // Extra 20px padding
            
            // Smooth scroll to element with navbar offset
            window.scrollTo({
                top: Math.max(0, elementTop),
                behavior: 'smooth'
            });
        }
    }
    
    // Register a route with its handler
    register(path, handler) {
        this.routes.set(path, handler);
    }
    
    // Navigate to a route using history API
    navigate(path) {
        
        // If SeedCardApp is available, use its navigation system instead
        // SeedCardApp.navigateToRoute now handles history.pushState internally
        if (window.app && window.app.navigateToRoute) {
            window.app.navigateToRoute(path, true); // true = push to history
            return;
        }
        
        // Fallback to router's own navigation
        window.history.pushState(null, '', path);
        this.handleRouteChange();
    }
    
    // Get current route from pathname
    getCurrentRoute() {
        const pathname = window.location.pathname;
        return pathname === '' ? this.defaultRoute : pathname;
    }
    
    // Handle route changes
    handleRouteChange() {
        const route = this.getCurrentRoute();
        
        // If SeedCardApp is available, delegate to it for consistent routing
        if (window.app && window.app.navigateToRoute) {
            window.app.navigateToRoute(route, false); // false = don't push to history (already at URL)
            return;
        }
        
        // Fallback: Check for exact route match first
        if (this.routes.has(route)) {
            this.executeRoute(route);
        } 
        // Check for anchor routes (config/*, tokens, examples)
        else if (this.isAnchorRoute(route)) {
            this.handleAnchorRoute(route);
        }
        else {
            // Fallback to default route
            this.navigate(this.defaultRoute);
        }
    }
    
    // Check if route is an anchor within generator
    isAnchorRoute(route) {
        const anchorRoutes = ['/config/seed', '/config/domain', '/tokens', '/examples'];
        return anchorRoutes.includes(route);
    }
    
    // Handle anchor routes by showing generator and scrolling to section
    handleAnchorRoute(route) {
        
        // Hide all views first
        this.hideAllViews();
        
        // Update current route to the anchor route (not /generator)
        this.currentRoute = route;
        
        // Update navigation state with the anchor route
        this.updateNavigation(route);
        
        // Show the generator view
        this.showView('generator-view');
        
        // Scroll to top first
        this.scrollToTop();
        
        // Then scroll to the appropriate section
        setTimeout(() => {
            const sectionMap = {
                '/config/seed': 'seed-section',
                '/config/domain': 'domain-section', 
                '/tokens': 'results',
                '/examples': 'password-examples'
            };
            
            const sectionId = sectionMap[route];
            if (sectionId) {
                this.scrollToSection(sectionId);
            }
        }, 100); // Small delay to ensure DOM is ready
    }
    
    // Execute a route handler
    executeRoute(route) {
        // Hide all views first
        this.hideAllViews();
        
        // Update current route
        this.currentRoute = route;
        
        // Update navigation state
        this.updateNavigation(route);
        
        // Execute route handler
        this.routes.get(route)();
    }
    
    // Scroll to a specific section within the generator
    scrollToSection(sectionId) {
        const section = document.getElementById(sectionId);
        if (section) {
            // Calculate navbar height for offset - use same logic as navigateSections
            const navbar = document.querySelector('.navbar');
            let navbarHeight = 80; // Default fallback
            
            if (navbar) {
                navbarHeight = navbar.getBoundingClientRect().height;
            }
            
            
            // Calculate position accounting for navbar with extra padding - same as navigateSections
            const elementPosition = section.getBoundingClientRect().top + window.pageYOffset;
            const offsetPosition = elementPosition - navbarHeight - 20; // Extra 20px padding
            
            
            // Smooth scroll to section with navbar offset
            window.scrollTo({
                top: Math.max(0, offsetPosition),
                behavior: 'smooth'
            });
        } else {
        }
    }
    
    // Scroll to top of page (for main route changes)
    scrollToTop() {
        window.scrollTo({
            top: 0,
            behavior: 'smooth'
        });
    }
    
    // Hide all view sections
    hideAllViews() {
        const views = document.querySelectorAll('.route-view');
        views.forEach(view => {
            view.style.display = 'none';
        });
    }
    
    // Update navigation highlighting - delegate to SeedCardApp
    updateNavigation(currentRoute) {
        // If SeedCardApp is available, let it handle navigation
        if (window.app && window.app.updateNavigationMenu) {
            window.app.updateNavigationMenu(currentRoute);
            return;
        }
        
        // Fallback: minimal navigation handling for Router-only scenarios
        const navItems = document.querySelectorAll('.nav-item, .nav-link');
        
        navItems.forEach(item => {
            const route = item.getAttribute('data-route') || item.getAttribute('href');
            item.classList.remove('active', 'nav-active');
            
            if (route === currentRoute || (route === '/generator' && this.isAnchorRoute(currentRoute))) {
                item.classList.add('active');
            }
        });
    }
    
    // Update additional navigation elements (breadcrumbs, etc.)
    updateAdditionalNavigation(currentRoute) {
        // Update any section-specific navigation within generator
        const allNavLinks = document.querySelectorAll('a[data-route], a[href^="/"]');
        allNavLinks.forEach(link => {
            const linkRoute = link.getAttribute('data-route') || link.getAttribute('href');
            link.classList.remove('nav-active', 'active');
            
            if (linkRoute === currentRoute) {
                link.classList.add('nav-active');
            }
        });
    }
    
    // Handle scroll events to update navigation based on visible section
    handleScroll() {
        // Only update navigation if we're on the generator page
        if (!this.currentRoute || (!this.currentRoute.startsWith('/config') && this.currentRoute !== '/generator' && this.currentRoute !== '/tokens' && this.currentRoute !== '/examples')) {
            return;
        }
        
        // Throttle scroll events for performance
        if (this.scrollTimeout) {
            clearTimeout(this.scrollTimeout);
        }
        
        this.scrollTimeout = setTimeout(() => {
            this.updateNavigationBasedOnScroll();
        }, 100);
    }
    
    // Update navigation highlighting based on which section is currently visible
    updateNavigationBasedOnScroll() {
        // Define sections and their corresponding routes
        const sections = [
            { id: 'seed-section', route: '/config/seed' },
            { id: 'domain-section', route: '/config/domain' },
            { id: 'options-section', route: '/config/domain' }, // Options section also maps to domain for nav highlighting
            { id: 'results', route: '/tokens' },
            { id: 'password-examples', route: '/examples' }
        ];
        
        const navbar = document.querySelector('.generator-header');
        const navbarHeight = navbar ? navbar.offsetHeight : 80;
        const scrollTop = window.pageYOffset || document.documentElement.scrollTop;
        
        let activeRoute = '/generator'; // Default to generator
        let closestSection = null;
        let closestDistance = Infinity;
        
        // Find the section that is closest to the top of the viewport
        for (const section of sections) {
            const element = document.getElementById(section.id);
            if (element) {
                const elementTop = element.offsetTop - navbarHeight;
                const distanceFromTop = Math.abs(scrollTop - elementTop);
                
                // If this section is past the scroll position and we're close to it
                if (scrollTop >= elementTop - 100 && distanceFromTop < closestDistance) {
                    closestDistance = distanceFromTop;
                    closestSection = section;
                    activeRoute = section.route;
                }
            }
        }
        
        // Update the current route if it changed (but don't push to history)
        if (activeRoute !== this.currentRoute) {
            this.currentRoute = activeRoute;
            
            // Update navigation highlighting without changing URL
            this.updateNavigation(activeRoute);
            
            // Update browser URL without triggering navigation
            window.history.replaceState(null, '', activeRoute);
        }
    }
    
    // Show a specific view section
    showView(viewId) {
        // First hide all views to ensure clean state
        this.hideAllViews();
        
        const view = document.getElementById(viewId);
        if (view) {
            view.style.display = 'block';
        } else {
            console.error('❌ View element not found:', viewId);
        }
    }
}

// Create global router instance
const router = new Router();

// Route handlers
router.register('/', () => {
    router.showView('home-view');
    router.scrollToTop();
});

router.register('/generator', () => {
    router.showView('generator-view');
    router.scrollToTop();
});

// Export for use in other modules
window.router = router;

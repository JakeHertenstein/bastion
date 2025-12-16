/**
 * Seed Card Generator - Vite Entry Point
 * 
 * This file serves as the minimal Vite entry point for CSS processing.
 * The actual application logic runs via script tags from the public/ directory.
 */

// Import stylesheets for Vite processing (hot reload, bundling)
import './spa-styles.css';
import './styles/main.css';

console.log('🌱 Seed Card Generator - Vite loaded');
console.log('📋 CSS files imported - main.css and spa-styles.css');

// Development mode helpers
if (import.meta.env?.DEV) {
    console.log('🛠️ Development mode - Hot reload enabled for CSS');
}

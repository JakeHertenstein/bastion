# Development & Release Process

## 📁 Project Structure (Hybrid Approach)

```
docs/web/
├── src/                    # 📁 Primary source code
│   ├── index.html         # Main HTML entry point
│   ├── main.js           # Vite entry point (minimal)
│   ├── spa-styles.css    # SPA-specific styling
│   ├── styles/           # CSS modules
│   └── ...               # Supporting modules
├── public/               # 📁 Working JavaScript files (Vite public assets)
│   ├── app.js           # Main application logic
│   ├── crypto.js        # Cryptographic functions
│   ├── generator.js     # Generator functionality
│   ├── router.js        # SPA routing
│   └── ...              # Additional assets
├── package.json          # Dependencies & scripts
├── vite.config.js        # Development config
├── vite.config.prod.js   # Production config
└── .gitignore           # Git ignore rules
```

## 🚀 Available Scripts

### Development
```bash
npm run dev              # Start development server (http://localhost:3000)
```

### Building
```bash
npm run build:dev        # Development build (with sourcemaps)
npm run build            # Production build (single-file, optimized)
npm run preview          # Preview production build locally
```

### Maintenance
```bash
npm run clean            # Remove all build artifacts
npm run release          # Clean + production build
npm run legacy:remove    # Remove legacy public-legacy/ directory
```

## 🔄 Development Workflow

### Daily Development
1. **Start development**: `npm run dev`
2. **Edit files in `src/` only** - this is the single source of truth
3. **Test changes** in browser at `http://localhost:3000`
4. **Build for production**: `npm run build` when ready

### No More Dual File Management!
- ✅ **Primary development in `src/`** - HTML, CSS, and Vite entry points
- ✅ **Working JavaScript in `public/`** - Served as static assets by Vite
- ✅ **Single build process** - Vite handles everything automatically
- ✅ **Automatic hot reload** for instant feedback on changes

## 📦 Build Outputs

### Development Build (`npm run build:dev`)
- **Output**: `dev-build/` directory
- **Features**: Sourcemaps, readable code, fast builds
- **Use**: Testing, debugging, development deployment

### Production Build (`npm run build`)
- **Output**: `dist/index.html` (single file)
- **Features**: Minified, optimized, all assets inlined
- **Use**: Final deployment, offline distribution

## 🎯 Best Practices

### File Organization
- **Source code**: Only edit files in `src/`
- **Assets**: Place any static assets in `src/` (they'll be processed by Vite)
- **No duplicates**: Removed `public/` directory confusion

### Version Control
- **Commit**: Only `src/`, configs, and docs
- **Ignore**: Build outputs (`dist/`, `dev-build/`), dependencies (`node_modules/`)
- **Legacy**: `public-legacy/` ignored (can be deleted when confident)

### Deployment
1. **Run**: `npm run release` (cleans + builds)
2. **Deploy**: Upload `dist/index.html` to web server
3. **Configure**: Set up SPA routing (history API fallback)

## 🔧 Migration from Legacy

### What Changed
- ✅ **Removed**: Duplicate files in `public/` directory
- ✅ **Simplified**: Single `src/` directory for all development
- ✅ **Improved**: Clear dev vs production builds
- ✅ **Automated**: No manual file copying needed

### If You Need Legacy Files
The old standalone files are temporarily in `public-legacy/`:
- Use `npm run legacy:remove` when confident they're not needed
- Or manually copy specific files if needed for reference

## 🎉 Benefits

- **🎯 Single Source of Truth**: Edit only `src/` files
- **⚡ Faster Development**: Vite's instant hot reload
- **🔄 No Sync Issues**: Eliminates duplicate file problems
- **📦 Better Builds**: Optimized production bundles
- **🧹 Cleaner Repo**: Less clutter, clearer structure
- **🚀 Easier Deployment**: Single-file output

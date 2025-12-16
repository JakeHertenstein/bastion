# Project Architecture & Development Flow

## 📁 Final Project Structure

```
docs/web/
├── src/                    # 🎯 Vite source directory
│   ├── index.html         # Main HTML (Vite entry point)
│   ├── main.js           # Vite entry point (CSS imports)
│   ├── spa-styles.css    # SPA-specific styles & UI components
│   └── styles/
│       └── main.css      # Main stylesheet
├── public/               # 📦 Static assets served by Vite
│   ├── app.js           # Main application logic
│   ├── crypto.js        # Cryptographic functions  
│   ├── generator.js     # Generator functionality
│   └── router.js        # SPA routing implementation
├── package.json          # Dependencies & scripts
├── vite.config.js        # Development configuration
├── vite.config.prod.js   # Production configuration  
├── .gitignore           # Git ignore rules
├── README.md            # Project documentation
└── ARCHITECTURE.md      # This architecture guide
```

## 🎯 Recent Major Improvements (Latest Release)

### **Token Click-to-Copy Feature**
- **Individual token copying**: Click any token in any matrix to copy to clipboard
- **Disabled text selection**: Prevents accidental text selection on matrices
- **Visual feedback**: Hover effects and "Click to copy" tooltips
- **Status integration**: Uses unified status bar messaging

### **Improved Card Layout Design**
- **Single card**: Copy Matrix button moved to header level (top-right)
- **Batch grid**: Unified header with centered title/hash, Copy Matrix button on right
- **Modal cards**: Reuse exact single card layout and styling
- **Visual cohesion**: Header and grid appear as joined elements

### **Error Handling & Status System**
- **Unified status messages**: All feedback through navbar status bar
- **Removed duplicate notifications**: Eliminated blue popup messages
- **Auto-generation graceful failures**: Silent handling for empty inputs
- **SLIP-39 modal prevention**: Fixed page load errors

### **Navigation & UX Enhancements** 
- **Fixed scroll positioning**: Proper navbar height accounting
- **Keyboard shortcuts**: Auto-close modals when switching modes
- **Batch grid improvements**: Index-only cells with shared prefix/hash header

## 🎯 Clear Separation of Concerns

### `/src/` Directory (Vite Sources)
- **Purpose**: Files that Vite processes and transforms
- **Contains**: HTML, CSS, Vite entry points
- **Processed**: Hot reload, CSS bundling, dev transformations

### `/public/` Directory (Static Assets)  
- **Purpose**: Files served as-is by Vite (no processing)
- **Contains**: Working JavaScript application files
- **Served**: Directly to browser without transformation

## 🔄 Development Workflow

### Daily Development
```bash
npm run dev              # Start development server
# Edit files in src/ for HTML/CSS
# Edit files in public/ for JavaScript functionality  
# All changes auto-reload in browser
```

### Building for Production
```bash
npm run build           # Production build (single file)
npm run build:dev       # Development build (with sourcemaps)
npm run preview         # Preview production build
```

### Maintenance
```bash
npm run clean           # Remove build artifacts
npm run release         # Clean + production build
```

## ⚙️ How It Works

### Development Mode (npm run dev)
1. **Vite serves** `src/index.html` as the main page
2. **CSS imported** via `main.js` → processed by Vite (hot reload)
3. **JavaScript loaded** via `<script>` tags → served from `public/` (static)
4. **Router, crypto, app logic** → runs in global scope as designed
5. **Hot reload** works for CSS/HTML changes
6. **Manual refresh** needed for JavaScript changes (by design)

### Production Build (npm run build)
1. **Vite bundles** everything from `src/` and `public/`
2. **Single HTML file** output with all assets inlined
3. **CSS minified** and embedded
4. **JavaScript concatenated** and embedded
5. **Ready for deployment** as single file

## 🎯 File Editing Guidelines

### When to Edit `src/` Files
- **HTML structure** (`src/index.html`)
- **CSS styling** (`src/spa-styles.css`, `src/styles/main.css`)
- **Vite configuration** (`main.js` - minimal entry point)

### When to Edit `public/` Files  
- **Application logic** (`public/app.js`)
- **Crypto functions** (`public/crypto.js`)
- **Generator features** (`public/generator.js`)
- **Router functionality** (`public/router.js`)

## 🚀 Deployment Strategy

### Single-File Distribution
- **Command**: `npm run build`
- **Output**: `dist/index.html` (complete standalone file)
- **Deploy**: Upload single file to any web server
- **Benefits**: Offline-capable, no dependencies

### Multi-File Distribution (Development)
- **Command**: `npm run build:dev`
- **Output**: `dev-build/` directory
- **Use**: Development/testing deployment with sourcemaps

## 🧹 Cleanup & Maintenance

### What to Keep
- ✅ `src/` - Vite source files
- ✅ `public/` - Working JavaScript files  
- ✅ Build configs (`vite.config.js`, `package.json`)
- ✅ Documentation (`README.md`, this file)

### What's Clean
- ✅ No duplicate files
- ✅ Clear separation of concerns
- ✅ Single source of truth for each file type
- ✅ Efficient build pipeline

## 🎉 Benefits of This Architecture

- **🎯 Clear Roles**: Each directory has a specific purpose
- **⚡ Fast Development**: Vite hot reload for styles, stable JS loading
- **📦 Optimized Builds**: Single-file production outputs
- **🔧 Maintainable**: No complex build steps or file duplication
- **🚀 Deployable**: Works on any static hosting
- **🔒 Secure**: Client-side only, no data transmission
- **📱 Responsive**: Works across desktop, tablet, and mobile
- **♿ Accessible**: Keyboard navigation and screen reader support

## 🌟 Key Features & Capabilities

### **Multi-Source Seed Generation**
- **Simple seeds**: Direct phrase-to-seed conversion
- **BIP-39 mnemonics**: Standard crypto wallet compatibility  
- **SLIP-39 shares**: Shamir's Secret Sharing support
- **Configurable iterations**: Adjustable PBKDF2 rounds

### **Token Matrix Management**
- **10×10 grids**: 100 deterministic tokens per card
- **Click-to-copy**: Individual token clipboard access
- **Visual feedback**: Hover effects and selection states
- **Coordinate system**: A0-J9 addressing scheme

### **Card Generation Modes**
- **Single cards**: Individual card generation with full preview
- **Batch generation**: 100-card sets with grid navigation
- **Modal viewing**: Detailed card inspection with same layout
- **Export options**: PDF download and print capabilities

### **User Experience**
- **Keyboard shortcuts**: Full keyboard navigation support
- **Auto-generation**: Live preview updates on input changes
- **Status feedback**: Unified status bar messaging system
- **Error handling**: Graceful failure with helpful messages

### **Security Features**
- **Rate limiting**: Prevents abuse and resource exhaustion
- **Input validation**: Comprehensive seed phrase validation
- **Memory cleanup**: Automatic sensitive data clearing
- **Offline operation**: No network requirements or data transmission

## 🔮 Future Improvements

When ready for full modularization:
1. **Migrate JavaScript** from `public/` to ES modules in `src/`
2. **Use Vite imports** instead of global script tags
3. **Tree shaking** for smaller bundles
4. **TypeScript** for better development experience

For now, this hybrid approach preserves all functionality while providing modern development tools.
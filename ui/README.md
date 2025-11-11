# SecureAPIs React Dashboard

A modern, real-time monitoring dashboard for the SecureAPIs security middleware, built with React, TypeScript, and Tailwind CSS.

## Features

- **Real-time Dashboard**: Live metrics, threat level monitoring, and security status
- **Request Tracking**: View and filter API requests with detailed statistics
- **Alert Management**: Monitor security alerts with severity levels
- **Dynamic Settings**: Customize refresh intervals, themes, and alert thresholds
- **Live Charts**: Visualize request trends and block rates using Recharts
- **Responsive Design**: Beautiful dark-themed UI that works on all devices

## Architecture

```
src/
├── main.tsx           # React entry point
├── App.tsx            # Main app component with routing
├── index.css          # Global styles with Tailwind
├── api.ts             # Axios API client with type definitions
├── store.ts           # Zustand state management
└── components/
    ├── Dashboard.tsx  # Main dashboard view
    ├── RequestTracker.tsx # Request statistics
    ├── Alerts.tsx     # Alert management
    └── Settings.tsx   # Configuration panel
```

## Getting Started

### Prerequisites

- Node.js 18+ and npm/yarn
- Rust backend running on `http://localhost:3000`

### Installation

```bash
# Install dependencies
npm install

# Start development server (port 5173)
npm run dev

# Build for production
npm run build

# Preview production build
npm run preview
```

## Technologies

- **Framework**: React 18 with TypeScript
- **Build Tool**: Vite
- **Styling**: Tailwind CSS
- **State Management**: Zustand
- **Charts**: Recharts
- **HTTP Client**: Axios
- **Icons**: Lucide React
- **API Target**: Rust Axum backend on localhost:3000

## API Integration

The dashboard connects to the following API endpoints:

- `GET /api/ui/dashboard` - Full dashboard data
- `GET /api/ui/metrics` - Real-time metrics
- `GET /api/ui/alerts` - Security alerts
- `GET /api/ui/requests` - Request statistics
- `POST /api/ui/request/track` - Track new request

## Development

### File Structure

```
ui/
├── src/
│   ├── components/      # React components
│   ├── api.ts          # API client and types
│   ├── store.ts        # Zustand store
│   ├── App.tsx         # Main component
│   ├── main.tsx        # Entry point
│   └── index.css       # Global styles
├── index.html          # HTML template
├── vite.config.ts      # Vite configuration
├── tailwind.config.js  # Tailwind configuration
├── postcss.config.js   # PostCSS configuration
├── tsconfig.json       # TypeScript configuration
└── package.json        # Dependencies
```

### Key Components

#### Dashboard
Real-time display of security metrics, threat levels, and system status. Includes:
- Threat level indicator
- Metric cards (requests, blocks, rate limits, auth failures)
- Request trend charts
- Top blocked IPs
- Security status panel

#### Request Tracker
Detailed view of API requests with:
- Search and filtering capabilities
- Sort by count or percentage
- Status indicators
- Visual percentage bars
- Summary statistics

#### Alerts
Alert management interface with:
- Severity levels (critical, warning, info)
- Alert dismissal
- Expandable details
- Summary cards

#### Settings
Configuration panel for:
- Theme selection (dark/light)
- Auto-refresh toggle and interval
- Threat alert level
- System information display

## State Management

Using Zustand for global state:

```typescript
// Example usage
const dashboard = useAppStore((state) => state.dashboard)
const setDashboard = useAppStore((state) => state.setDashboard)
```

## Styling

The dashboard uses Tailwind CSS with a custom color scheme:
- Background: Slate 950 (`#0f172a`)
- Primary: Cyan 400
- Accent: Green 400
- Dark theme optimized for security monitoring

## Building for Production

```bash
npm run build
```

This creates an optimized build in the `dist/` directory, ready to be served as a static site.

## Troubleshooting

### Backend Connection Issues
Make sure the Rust backend is running on `http://localhost:3000`:
```bash
# In the secureapis root directory
cargo run --example ui_server
```

### Dependencies Not Installing
Clear cache and reinstall:
```bash
rm -rf node_modules package-lock.json
npm install
```

### Port Already in Use
Change the port in `vite.config.ts`:
```typescript
server: {
  port: 5174, // Change to desired port
}
```

## Future Enhancements

- [ ] WebSocket support for real-time updates
- [ ] Data export (CSV, JSON)
- [ ] Custom dashboard layouts
- [ ] User authentication/roles
- [ ] Historical data view
- [ ] Performance profiling tools
- [ ] Mobile app companion

## License

MIT License - See LICENSE file in project root

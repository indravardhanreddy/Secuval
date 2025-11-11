# 🌐 SecureAPIs UI Frontend Blueprint

This document provides a blueprint for building a web-based frontend dashboard for the SecureAPIs security middleware.

## Architecture Overview

```
┌─────────────────────────────────────────────────────┐
│         Web Browser (React/Vue/Svelte)              │
│  ┌──────────────────────────────────────────────┐  │
│  │    Dashboard UI Components                   │  │
│  │  • Threat Level Gauge                        │  │
│  │  • Real-time Metrics Chart                   │  │
│  │  • Alert List & Management                   │  │
│  │  • Request Tracking Table                    │  │
│  │  • Settings Panel                            │  │
│  └──────────────────────────────────────────────┘  │
└─────────────────┬──────────────────────────────────┘
                  │ HTTP/WebSocket
                  │ RESTful API
                  ▼
┌─────────────────────────────────────────────────────┐
│         Axum Web Server (Rust Backend)              │
│  ┌──────────────────────────────────────────────┐  │
│  │    API Endpoints                             │  │
│  │  GET  /api/ui/dashboard    → Dashboard data │  │
│  │  GET  /api/ui/metrics      → Metrics data   │  │
│  │  GET  /api/ui/alerts       → Alert list     │  │
│  │  POST /api/ui/alerts/:id/dismiss → Dismiss  │  │
│  │  PUT  /api/ui/settings     → Update config  │  │
│  │  GET  /api/ui/requests     → Request logs   │  │
│  └──────────────────────────────────────────────┘  │
└─────────────────┬──────────────────────────────────┘
                  │
                  ▼
┌─────────────────────────────────────────────────────┐
│         UI State Manager (Rust Backend)             │
│  • Request tracking & logging                       │
│  • Alert management                                 │
│  • Dynamic settings                                 │
│  • Metrics collection                               │
│  • Configuration management                         │
└─────────────────────────────────────────────────────┘
```

## Frontend Technology Stack Recommendations

### Recommended Stack
- **Framework**: React 18+ with TypeScript
- **State Management**: TanStack Query (React Query) + Zustand
- **UI Components**: shadcn/ui or Material-UI
- **Charts**: Recharts or Chart.js
- **Real-time**: WebSocket via Socket.io or native WebSocket
- **Styling**: Tailwind CSS
- **Build Tool**: Vite

### Alternative Options
- **Vue 3** with Composition API
- **Svelte** with SvelteKit
- **Next.js** for full-stack approach

## Component Structure

```
src/
├── components/
│   ├── Dashboard/
│   │   ├── DashboardContainer.tsx
│   │   ├── ThreatLevelGauge.tsx
│   │   ├── MetricsChart.tsx
│   │   ├── TopBlockedIPs.tsx
│   │   └── SystemHealth.tsx
│   │
│   ├── RequestTracking/
│   │   ├── RequestTable.tsx
│   │   ├── RequestSearch.tsx
│   │   ├── RequestFilters.tsx
│   │   ├── RequestDetails.tsx
│   │   └── TrafficTrends.tsx
│   │
│   ├── Alerts/
│   │   ├── AlertList.tsx
│   │   ├── AlertNotification.tsx
│   │   ├── AlertDetails.tsx
│   │   └── AlertHistory.tsx
│   │
│   ├── Settings/
│   │   ├── SettingsPanel.tsx
│   │   ├── RateLimitSettings.tsx
│   │   ├── ValidationSettings.tsx
│   │   ├── AuthSettings.tsx
│   │   └── PreferencesSettings.tsx
│   │
│   ├── Metrics/
│   │   ├── MetricsOverview.tsx
│   │   ├── SecurityMetrics.tsx
│   │   ├── PerformanceMetrics.tsx
│   │   ├── ThreatSources.tsx
│   │   └── ThreatDistribution.tsx
│   │
│   ├── Common/
│   │   ├── Navbar.tsx
│   │   ├── Sidebar.tsx
│   │   ├── LoadingSpinner.tsx
│   │   ├── ErrorBoundary.tsx
│   │   └── ThemeToggle.tsx
│   │
│   └── Layout/
│       ├── MainLayout.tsx
│       ├── DashboardLayout.tsx
│       └── SettingsLayout.tsx
│
├── hooks/
│   ├── useDashboard.ts
│   ├── useRequests.ts
│   ├── useAlerts.ts
│   ├── useMetrics.ts
│   ├── useSettings.ts
│   └── useWebSocket.ts
│
├── services/
│   ├── api/
│   │   ├── dashboardApi.ts
│   │   ├── requestsApi.ts
│   │   ├── alertsApi.ts
│   │   ├── metricsApi.ts
│   │   ├── settingsApi.ts
│   │   └── client.ts (Axios/Fetch wrapper)
│   │
│   └── websocket/
│       ├── wsClient.ts
│       └── eventHandlers.ts
│
├── store/
│   ├── dashboardStore.ts
│   ├── alertsStore.ts
│   ├── settingsStore.ts
│   └── metricsStore.ts
│
├── types/
│   ├── api.ts
│   ├── dashboard.ts
│   ├── alerts.ts
│   ├── metrics.ts
│   └── settings.ts
│
├── utils/
│   ├── formatters.ts
│   ├── validators.ts
│   ├── constants.ts
│   └── helpers.ts
│
├── pages/
│   ├── Dashboard.tsx
│   ├── Requests.tsx
│   ├── Alerts.tsx
│   ├── Metrics.tsx
│   ├── Settings.tsx
│   └── NotFound.tsx
│
└── App.tsx
```

## API Integration Examples

### React Hook for Dashboard

```typescript
import { useQuery } from '@tanstack/react-query';

export function useDashboard() {
  return useQuery({
    queryKey: ['dashboard'],
    queryFn: async () => {
      const response = await fetch('/api/ui/dashboard');
      return response.json();
    },
    refetchInterval: 5000, // Refresh every 5 seconds
  });
}
```

### Real-time Alerts with WebSocket

```typescript
import { useEffect, useState } from 'react';

export function useAlertStream() {
  const [alerts, setAlerts] = useState([]);

  useEffect(() => {
    const ws = new WebSocket('ws://localhost:3000/api/ui/alerts/stream');
    
    ws.onmessage = (event) => {
      const alert = JSON.parse(event.data);
      setAlerts(prev => [alert, ...prev]);
    };

    return () => ws.close();
  }, []);

  return alerts;
}
```

### Settings Management

```typescript
import { useMutation, useQuery } from '@tanstack/react-query';

export function useSettings() {
  const { data: settings } = useQuery({
    queryKey: ['settings'],
    queryFn: () => fetch('/api/ui/settings').then(r => r.json()),
  });

  const updateSettings = useMutation({
    mutationFn: (newSettings) =>
      fetch('/api/ui/settings', {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(newSettings),
      }).then(r => r.json()),
  });

  return { settings, updateSettings };
}
```

## Dashboard Components

### Threat Level Gauge
Displays the current threat level with color coding:
- Green: Low (< 1% blocks)
- Yellow: Medium (1-5% blocks)
- Orange: High (5-10% blocks)
- Red: Critical (> 10% blocks)

### Metrics Chart
Real-time line chart showing:
- Requests over time
- Block rate
- Response times (avg, p95, p99)

### Request Table
Sortable, filterable table with:
- Timestamp
- HTTP method
- Path
- Client IP
- Status code
- Response time
- Threat score
- Block status

### Alert Management
- List of active alerts
- Color-coded by severity
- One-click dismiss
- Alert history
- Email/Slack notifications (if configured)

### Settings Panel
Dynamic forms for:
- Rate limiting configuration
- Validation settings
- Authentication options
- Threat detection levels
- UI preferences (theme, refresh rate, etc.)

## TypeScript Types

```typescript
// Dashboard types
interface DashboardData {
  metrics: MetricsSnapshot;
  topBlockedIps: IpBlockInfo[];
  threatLevel: 'Low' | 'Medium' | 'High' | 'Critical';
  recentEvents: DashboardEvent[];
  securityStatus: SecurityStatus;
  uptimeSeconds: number;
}

// Alert types
interface Alert {
  id: string;
  timestamp: string;
  title: string;
  message: string;
  severity: 'Info' | 'Warning' | 'Critical';
  type: AlertType;
  dismissed: boolean;
}

// Request types
interface RequestLog {
  id: string;
  timestamp: string;
  method: string;
  path: string;
  clientIp: string;
  userAgent: string;
  statusCode: number;
  responseTimeMs: number;
  threatScore: number;
  blocked: boolean;
}

// Metrics types
interface MetricsSnapshot {
  totalRequests: number;
  blockedRequests: number;
  rateLimited: number;
  blockRate: number;
  avgResponseTimeMs: number;
  p95ResponseTimeMs: number;
}

// Settings types
interface SecuritySettings {
  rateLimit: {
    enabled: boolean;
    requestsPerWindow: number;
    windowDurationSecs: number;
    burstSize: number;
  };
  validation: {
    enabled: boolean;
    sqlInjectionCheck: boolean;
    xssCheck: boolean;
    sanitizeInput: boolean;
  };
  auth: {
    enabled: boolean;
    requireAuth: boolean;
    mfaEnabled: boolean;
  };
}
```

## Features to Implement

### Phase 1: MVP
- [ ] Dashboard with basic metrics
- [ ] Request tracking table
- [ ] Alert list
- [ ] Basic settings panel
- [ ] Real-time updates every 5 seconds

### Phase 2: Enhanced
- [ ] WebSocket for real-time updates
- [ ] Advanced filtering and search
- [ ] Export/Import settings
- [ ] Detailed request analytics
- [ ] Threat trend charts

### Phase 3: Advanced
- [ ] User authentication
- [ ] Role-based access control
- [ ] Custom dashboards
- [ ] Report generation
- [ ] Integration with external services (Slack, PagerDuty)
- [ ] Mobile-responsive design

## Sample HTML Structure (Minimal)

```html
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>SecureAPIs Dashboard</title>
  <link rel="stylesheet" href="/styles/main.css">
</head>
<body>
  <div id="root"></div>
  <script type="module" src="/src/main.tsx"></script>
</body>
</html>
```

## Development Workflow

1. **Setup**
   ```bash
   npm create vite@latest secureapis-ui -- --template react-ts
   cd secureapis-ui
   npm install
   ```

2. **Install Dependencies**
   ```bash
   npm install @tanstack/react-query zustand recharts axios
   npm install -D tailwindcss postcss autoprefixer
   ```

3. **Configure API Client**
   ```typescript
   const API_BASE = process.env.REACT_APP_API_URL || 'http://localhost:3000';
   
   export const apiClient = axios.create({
     baseURL: API_BASE,
     timeout: 10000,
   });
   ```

4. **Run Development Server**
   ```bash
   npm run dev
   ```

5. **Build for Production**
   ```bash
   npm run build
   ```

## Deployment

### Docker Container
```dockerfile
FROM node:18-alpine AS builder
WORKDIR /app
COPY package*.json .
RUN npm install
COPY . .
RUN npm run build

FROM nginx:alpine
COPY --from=builder /app/dist /usr/share/nginx/html
COPY nginx.conf /etc/nginx/conf.d/default.conf
EXPOSE 80
CMD ["nginx", "-g", "daemon off;"]
```

### Environment Configuration
```env
REACT_APP_API_URL=https://api.example.com
REACT_APP_WS_URL=wss://api.example.com
REACT_APP_ENV=production
```

## Security Considerations

1. **HTTPS Only**: Always use HTTPS in production
2. **CORS**: Configure CORS properly on backend
3. **Authentication**: Implement JWT or session-based auth
4. **XSS Protection**: Sanitize all user input
5. **CSRF Protection**: Include CSRF tokens in requests
6. **Rate Limiting**: Apply rate limits to frontend API calls
7. **Content Security Policy**: Set appropriate CSP headers
8. **API Keys**: Never expose API keys in frontend code

## Performance Optimization

1. **Code Splitting**: Lazy load components with React.lazy
2. **Memoization**: Use React.memo for expensive components
3. **Virtual Scrolling**: For large request tables
4. **Image Optimization**: Use WebP with fallbacks
5. **Bundle Analysis**: Monitor bundle size with rollup-plugin-visualizer
6. **Caching**: Implement proper cache headers

## Monitoring & Analytics

1. **Error Tracking**: Sentry or similar
2. **Performance Monitoring**: Web Vitals
3. **User Analytics**: Google Analytics or Plausible
4. **Crash Reporting**: Bugsnag or similar

## References

- React: https://react.dev
- TypeScript: https://www.typescriptlang.org
- Tailwind CSS: https://tailwindcss.com
- Recharts: https://recharts.org
- TanStack Query: https://tanstack.com/query/latest
- Axum: https://github.com/tokio-rs/axum

# client/ — CyberForecaster dashboard

React 19 + Vite + Tailwind CSS single-page dashboard. It talks to the backend in
`../capture-service` over REST and WebSocket.

```bash
npm install
npm run dev        # http://127.0.0.1:5173
npm run build      # production build into dist/
```

The backend address defaults to `127.0.0.1:8080`. To point the dashboard at another machine, copy
`.env.example` to `.env` and set `VITE_CAPTURE_HOST` / `VITE_CAPTURE_PORT`.

| Path | Contents |
| :--- | :--- |
| `src/App.jsx` | layout, sidebar, page switching |
| `src/pages/LandingPage.jsx` | landing screen |
| `src/pages/LiveTraffic.jsx` | Live Telemetry — interface selection, live charts, PCAP/CSV export |
| `src/pages/UploadAnalysis.jsx` | File Upload — PCAP/CSV upload and processing status |
| `src/pages/AttackForecast.jsx` | Attack Forecast — security state, risk forecast, MITRE progression, SHAP, evidence |

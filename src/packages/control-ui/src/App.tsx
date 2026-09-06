import { useEffect } from 'react';
import { HashRouter, Navigate, Route, Routes } from 'react-router-dom';
import { TelemetryService } from './api/TelemetryService';
import { AppLayout } from './AppLayout';
import { Dashboard } from './pages/Dashboard';
import { Health } from './pages/Health';
import { Dns } from './pages/Dns';
import { Logs } from './pages/Logs';
import { Connections } from './pages/Connections';
import { Capabilities } from './pages/Capabilities';
import { Operations } from './pages/Operations';
import { Profiles } from './pages/Profiles';
import { Rules } from './pages/Rules';
import { Settings } from './pages/Settings';
import { NetworkCockpit } from './pages/NetworkCockpit';

function App() {
  useEffect(() => {
    void TelemetryService.connect();
    return () => {
      TelemetryService.disconnect();
    };
  }, []);

  return (
    <HashRouter>
      <Routes>
        <Route path="/" element={<AppLayout />}>
          <Route index element={<Dashboard />} />
          <Route path="cockpit" element={<NetworkCockpit />} />
          <Route path="health" element={<Health />} />
          <Route path="rules" element={<Rules />} />
          <Route path="dns" element={<Dns />} />
          <Route path="logs" element={<Logs />} />
          <Route path="connections" element={<Connections />} />
          <Route path="capabilities" element={<Capabilities />} />
          <Route path="operations" element={<Operations />} />
          <Route path="profiles" element={<Profiles />} />
          <Route path="settings" element={<Settings />} />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Route>
      </Routes>
    </HashRouter>
  );
}

export default App;

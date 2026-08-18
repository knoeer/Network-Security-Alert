import React from 'react';
import { Routes, Route, Navigate } from 'react-router-dom';
import Layout from './components/Layout';
import Dashboard from './pages/Dashboard';
import EventList from './pages/EventList';
import EventDetail from './pages/EventDetail';
import DeviceManager from './pages/DeviceManager';
import DeviceDetail from './pages/DeviceDetail';
import Topology from './pages/Topology';
import Settings from './pages/Settings';
import AlertWindow from './pages/AlertWindow';

const App: React.FC = () => {
  return (
    <Routes>
      <Route path="/" element={<Layout />}>
        <Route index element={<Navigate to="/dashboard" replace />} />
        <Route path="dashboard" element={<Dashboard />} />
        <Route path="events" element={<EventList />} />
        <Route path="events/:id" element={<EventDetail />} />
        <Route path="devices" element={<DeviceManager />} />
        <Route path="devices/:id" element={<DeviceDetail />} />
        <Route path="topology" element={<Topology />} />
        <Route path="settings" element={<Settings />} />
      </Route>
      <Route path="/alert" element={<AlertWindow />} />
    </Routes>
  );
};

export default App;

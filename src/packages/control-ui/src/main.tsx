import React from 'react';
import ReactDOM from 'react-dom/client';
import App from './App';
import './index.css';
import { initializeAppearance } from './lib/appearance';

initializeAppearance();

const root = document.getElementById('root');
if (!root) {
  throw new Error('LumiNet desktop root element was not found');
}

ReactDOM.createRoot(root).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>,
);


if ('serviceWorker' in navigator) {
  window.addEventListener('load', () => {
    void navigator.serviceWorker.register('./sw.js', { scope: './' }).catch(() => {
      // Embedded webviews and restricted contexts may not expose service workers.
    });
  }, { once: true });
}

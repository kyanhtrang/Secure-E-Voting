import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import { BrowserRouter } from 'react-router';
import { App, AppBoundary } from './app';
import './styles.css';

createRoot(document.getElementById('root')!).render(<StrictMode><AppBoundary><BrowserRouter><App /></BrowserRouter></AppBoundary></StrictMode>);

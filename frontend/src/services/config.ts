// Centralized API configuration.
//
// DEMO MODE  (VITE_USE_MOCK_DATA=true, the default):
//   → the app uses temporary demo data from src/data/
// REAL API MODE (VITE_USE_MOCK_DATA=false):
//   → the app calls the Django REST Framework backend and surfaces real
//     API errors instead of falling back to demo data.
export const USE_MOCK_DATA =
  (import.meta.env.VITE_USE_MOCK_DATA as string | undefined ?? 'true') !== 'false';

export const API_BASE_URL =
  (import.meta.env.VITE_API_URL as string | undefined) || 'http://127.0.0.1:8000/api/';

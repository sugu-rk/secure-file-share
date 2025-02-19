// src/routes/AppRouter.js
import React, { useEffect } from 'react';
import { Route, Routes, Navigate, useLocation } from 'react-router-dom'; // Correct import now!
import LandingPage from '../pages/LandingPage';
import LoginPage from '../pages/LoginPage';
import RegisterPage from '../pages/RegisterPage';
import DashboardPage from '../pages/DashboardPage';
import AdminDashboardPage from '../pages/AdminDashboardPage';
import { useSelector, useDispatch } from 'react-redux';
import { loginSuccess } from '../redux/authSlice';
import store from '../redux/store'; // <-- ADD THIS IMPORT
import apiClient from '../services/apiClient';
import { PersistGate } from 'redux-persist/integration/react';



const ProtectedRoute = ({ children, isAdminRoute }) => {
    const isAuthenticated = useSelector((state) => state.auth.isAuthenticated);
    const isAdmin = useSelector((state) => state.auth.user?.is_staff || state.auth.user?.is_superuser);
  
    console.log("ProtectedRoute - isAuthenticated:", isAuthenticated, "isAdminRoute:", isAdminRoute); // ADDED LOG
  
    if (!isAuthenticated) {
      console.log("ProtectedRoute - Redirecting to /login because !isAuthenticated"); // ADDED LOG
      return <Navigate to="/login" replace />;
    }
  
    if (isAdminRoute && !isAdmin) {
      console.log("ProtectedRoute - Redirecting to /dashboard because !isAdmin for admin route"); // ADDED LOG
      return <Navigate to="/dashboard" replace />;
    }
  
    return children;
  };

  
function AppRouter() {
  const dispatch = useDispatch();
  const location = useLocation(); // Using useLocation - GOOD!
  
  const isAuthenticated = useSelector((state) => state.auth.isAuthenticated); // Get isAuthenticated from Redux

  useEffect(() => {
    const refreshAccessToken = async () => {
      // Enhanced condition: Check path AND isAuthenticated state
      if (location.pathname !== '/login' && location.pathname !== '/register' && location.pathname !== '/' && isAuthenticated) { // <-- ADDED isAuthenticated CHECK
        console.log("AppRouter.js - refreshAccessToken: Attempting to refresh access token (conditional + auth check)...");
        try {
          const response = await apiClient.post('/api/auth/token/refresh/');
          console.log("AppRouter.js - refreshAccessToken: Response status:", response.status);
          console.log("AppRouter.js - refreshAccessToken: Response data:", response.data);
          if (response.status === 200) {
            const { access: newAccessToken } = response.data;
            dispatch(loginSuccess({ accessToken: newAccessToken }));
            console.log("AppRouter.js - refreshAccessToken: Auth state after successful refresh and dispatch:", store.getState().auth);
          } else {
            console.log("AppRouter.js - refreshAccessToken: Access token refresh failed (status !200), staying logged out.");
          }
        } catch (error) {
          console.error("AppRouter.js - refreshAccessToken: Error during access token refresh on app load:", error);
          console.error("AppRouter.js - refreshAccessToken: Axios error details:", error.response);
        }
      } else {
        console.log("AppRouter.js - refreshAccessToken: Skipping token refresh on login/register page or when not authenticated yet."); // More descriptive log
      }
    };

    refreshAccessToken();
  }, [dispatch, location.pathname, isAuthenticated]); // ADD isAuthenticated to dependency array - IMPORTANT

  return (
      <Routes>
        <Route path="/login" element={<LoginPage />} />
        <Route path="/" element={<LandingPage />} />
        <Route path="/register" element={<RegisterPage />} />
        <Route path="/dashboard" element={
          <ProtectedRoute>
            <DashboardPage />
          </ProtectedRoute>
        } />
        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
  );
}

export default AppRouter;
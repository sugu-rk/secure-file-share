// src/components/auth/LogoutButton.js
import React from 'react';
import apiClient from '../../services/apiClient';
import { useDispatch } from 'react-redux';
import { logout } from '../../redux/authSlice';
import { useNavigate } from 'react-router-dom';

function LogoutButton() {
  const dispatch = useDispatch();
  const navigate = useNavigate();

  const handleLogout = async () => {
    try {
      const response = await apiClient.apiClientWithInterceptor.post('/api/auth/logout/', true); // API call to /auth/logout/
      if (response.status === 200) {
        // Logout successful
        dispatch(logout()); // Dispatch logout action to clear Redux state
        console.log('Logout successful');
        navigate('/login'); // Redirect to login page
        window.location.reload(true); // <--- Force full page reload after redirect
      } else {
        // Handle logout error (optional - logout is usually handled client-side anyway)
        console.error('Logout failed:', response.status, response.data);
        // You could display an error message to the user if needed, but logout usually clears session client-side regardless of backend success.
      }
    } catch (error) {
      console.error('Logout API Error:', error);
      // Handle API error (optional - similar to success, client-side logout is often sufficient)
    }
  };

  return (
    <button onClick={handleLogout}>Logout</button>
  );
}

export default LogoutButton;
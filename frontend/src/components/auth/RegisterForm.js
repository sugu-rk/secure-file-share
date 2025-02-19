// src/components/auth/RegisterForm.js
import React, { useState } from 'react';
import { FontAwesomeIcon } from '@fortawesome/react-fontawesome';
import { faEye, faEyeSlash } from '@fortawesome/free-solid-svg-icons';
import apiClient from '../../services/apiClient'; // Import apiClient
import { useDispatch } from 'react-redux'; // Import useDispatch hook
import { loginSuccess } from '../../redux/authSlice'; // Import loginSuccess action
import { useNavigate } from 'react-router-dom'; // Import useNavigate for redirection
import store from '../../redux/store'; // Add this line: Import your Redux store

function RegisterForm({ onRegistrationSuccess }) {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [password2, setPassword2] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [passwordStrength, setPasswordStrength] = useState('');
  const [error, setError] = useState('');
  const [successMessage, setSuccessMessage] = useState('');
  const dispatch = useDispatch(); // Get dispatch function from Redux
  const navigate = useNavigate(); // Get navigate function from React Router

  const handleEmailChange = (e) => setEmail(e.target.value);
  const handlePasswordChange = (e) => {
    setPassword(e.target.value);
    updatePasswordStrength(e.target.value);
  };
  const handlePassword2Change = (e) => setPassword2(e.target.value);
  const handleShowPasswordChange = () => setShowPassword(!showPassword);

  const updatePasswordStrength = (password) => {
    if (password.length < 8) {
      setPasswordStrength('Too weak');
    } else if (password.length < 12) {
      setPasswordStrength('Medium');
    } else {
      setPasswordStrength('Strong');
    }
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');
    setSuccessMessage('');

    if (!email || !password || !password2) {
      setError('Please fill in all fields.');
      return;
    }
    if (password !== password2) {
      setError('Passwords do not match.');
      return;
    }
    if (passwordStrength === 'Too weak') {
      setError('Password is too weak. Please use a stronger password.');
      return;
    }
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
      setError('Invalid email format.');
      return;
    }

    try {
      const response = await apiClient.post('/api/auth/register/', { // Use apiClient.post
        username: email, // Backend expects 'username' as email
        password: password,
        password2: password2,
      });

      if (response.status === 201) { // Successful registration (201 Created)
        const { access, message } = response.data; // Assuming API returns access_token and message
        dispatch(loginSuccess({ accessToken: access, username: email })); // Store accessToken in Redux
        console.log("Access Token after registration:", store.getState().auth.accessToken); // ADD THIS LINE
        setSuccessMessage(message || 'Registration successful! Redirecting to MFA setup...');
        // Redirect to MFA setup page or dialog (we will implement this next)
        // For now, let's just navigate to dashboard as a placeholder
        // navigate('/dashboard'); // Redirect to dashboard after successful registration (for now)
        onRegistrationSuccess(); // Trigger MFA dialog opening
      } else {
        // Handle unexpected success status codes if needed
        setError('Registration failed. Please try again.');
      }
    } catch (error) {
      console.error('Registration API Error:', error);
      if (error.response && error.response.data) {
        // Extract error messages from backend response (e.g., validation errors)
        const errorData = error.response.data;
        if (errorData.message) {
          setError(errorData.message); // Display backend message if available
        } else {
          // If no specific message, display generic error or validation errors if structured
          let detailedError = '';
          for (const key in errorData) {
            detailedError += `${key}: ${errorData[key].join(', ')}\n`; // Assuming errors are in format { field: [messages] }
          }
          setError(detailedError || 'Registration failed due to validation errors.');
        }
      } else {
        setError('Registration failed. Could not connect to server.'); // Network error or other issues
      }
    }
  };

  return (
    <form onSubmit={handleSubmit}>
      <h2>Register</h2>
      {error && <div className="error-message">{error}</div>}
      {successMessage && <div className="success-message">{successMessage}</div>}
      <div>
        <label htmlFor="email">Email:</label>
        <input type="email" id="email" value={email} onChange={handleEmailChange} required />
      </div>
      <div>
        <label htmlFor="password">Password:</label>
        <div className="password-input-group">
          <input
            type={showPassword ? 'text' : 'password'}
            id="password"
            value={password}
            onChange={handlePasswordChange}
            required
          />
          <span className="password-toggle-icon" onClick={handleShowPasswordChange}>
            <FontAwesomeIcon icon={showPassword ? faEyeSlash : faEye} />
          </span>
        </div>
        <div className="password-strength">{passwordStrength}</div>
      </div>
      <div>
        <label htmlFor="password2">Confirm Password:</label>
        <div className="password-input-group">
          <input
            type={showPassword ? 'text' : 'password'}
            id="password2"
            value={password2}
            onChange={handlePassword2Change}
            required
          />
          <span className="password-toggle-icon" onClick={handleShowPasswordChange}>
            <FontAwesomeIcon icon={showPassword ? faEyeSlash : faEye} />
          </span>
        </div>
      </div>
      <button type="submit">Register</button>
    </form>
  );
}

export default RegisterForm;
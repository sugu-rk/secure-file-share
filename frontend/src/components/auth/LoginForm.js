// src/components/auth/LoginForm.js
import React, { useState } from 'react';
import { FontAwesomeIcon } from '@fortawesome/react-fontawesome';
import { faEye, faEyeSlash } from '@fortawesome/free-solid-svg-icons';
import apiClient from '../../services/apiClient';
import { useDispatch } from 'react-redux';
import { loginSuccess } from '../../redux/authSlice';
import { useNavigate } from 'react-router-dom';

function LoginForm() {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [error, setError] = useState('');
  const [mfaRequired, setMfaRequired] = useState(false); // New state: Is MFA required?
  const [mfaToken, setMfaToken] = useState(''); // New state: OTP token input
  const [mfaVerificationError, setMfaVerificationError]
   = useState(''); // New state: MFA verification error
  const [loginUsername, setLoginUsername] = useState(''); // New state: Store username for MFA verify
  const dispatch = useDispatch(); // Get dispatch function
  const navigate = useNavigate(); // Get navigate function

  const handleEmailChange = (e) => setEmail(e.target.value);
  const handlePasswordChange = (e) => setPassword(e.target.value);
  const handleShowPasswordChange = () => setShowPassword(!showPassword);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError(''); // Clear general login errors
    setMfaVerificationError(''); // Clear MFA verification errors

    if (!email || !password) {
      setError('Please fill in all fields.');
      return;
    }
    console.log("Login attempt with:", email, password); // Debug log

    try {
      const response = await apiClient.post('/api/auth/login/', {
        username: email,
        password: password,
      });
      console.log("Login API Response:", response.data); // Debug log
      if (response.status === 200) {
        const { access, message, mfa_required } = response.data; // Get username from response

        if (mfa_required === true) {
          // MFA is required - Set mfaRequired state to true, store username
          console.log('MFA Required for login. Username:', email);
          setMfaRequired(true);
          setLoginUsername(email); // Store username for MFA verification
          // MFA verification UI will be shown conditionally based on mfaRequired state
        } else {
          // SFA Login Success - No MFA required
          dispatch(
            loginSuccess({ 
              accessToken: access, 
              username: email // Ensure a value is always set
            })
          );
          console.log('SFA Login Successful. Access Token:', access);
          navigate('/dashboard');
        }
      } else if (response.status === 401) {
        setError('Invalid credentials. Please check your email and password.');
      } else {
        setError('Login failed. Please try again.');
      }
    } catch (error) {
      console.error('Login API Error:', error);
      setError('Login failed. Could not connect to server.');
    }
  };


  const handleVerifyOTP = async () => {
    setMfaVerificationError(''); // Clear previous MFA verification errors

    if (!mfaToken) {
      setMfaVerificationError('Please enter the verification code.');
      return;
    }

    try {
      const response = await apiClient.post('/api/auth/mfa/verify/', { // API call to /auth/mfa/verify/
        token: mfaToken,
        username: loginUsername, // Use stored username for MFA verify
      },
      {
        headers: { Authorization: undefined }, // <--- Bypass interceptor for MFA Verify during LOGIN
      });

      if (response.status === 200) {
        // MFA Verification Success
        const { access, message } = response.data;
        dispatch(loginSuccess({ accessToken: access, username: loginUsername })); // Dispatch loginSuccess (use original email for user info)
        console.log('MFA Verification Successful. Access Token:', access);
        navigate('/dashboard'); // Redirect to dashboard
      } else if (response.status === 400) {
        // 400 Bad Request - Invalid MFA token
        setMfaVerificationError('Invalid verification code. Please try again.');
      } else {
        // Other error status codes during MFA verification
        setMfaVerificationError('MFA verification failed. Please try again.');
      }
    } catch (error) {
      console.error('MFA Verify API Error:', error);
      setMfaVerificationError('MFA verification failed. Could not connect to server.'); // Network error
    }
  };

  
  return (
    <form onSubmit={handleSubmit}>
      <h2>Login</h2>
      {error && <div className="error-message">{error}</div>}
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
      </div>

      {mfaRequired && ( // Conditional rendering for MFA Verification UI
        <div className="mfa-verification-section">
          <h3>Two-Factor Verification Required</h3>
          {mfaVerificationError && <div className="error-message">{mfaVerificationError}</div>}
          <div>
            <label htmlFor="mfa-token">Verification Code:</label>
            <input
              type="text"
              id="mfa-token"
              placeholder="Enter Verification Code"
              value={mfaToken}
              onChange={(e) => setMfaToken(e.target.value)}
              required
            />
          </div>
          <button type="button" onClick={handleVerifyOTP}> {/* Verify OTP button */}
            Verify OTP
          </button>
        </div>
      )}

      {!mfaRequired && <button type="submit">Login</button>} {/* Show Login button when MFA not required */}
    </form>
  );

  // ... (rest of LoginForm component, including handleVerifyOTP function - to be implemented next) ...
}

export default LoginForm;
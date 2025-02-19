// src/components/auth/MFASetupDialog.js
import React, { useState, useEffect } from 'react';
import { QRCodeCanvas } from 'qrcode.react';
import apiClient from '../../services/apiClient';
import { useDispatch, useSelector } from 'react-redux'; // Import useSelector
import { loginSuccess } from '../../redux/authSlice';
import { useNavigate } from 'react-router-dom';

function MFASetupDialog({ isOpen, onClose }) { // Remove username prop
  const [secret, setSecret] = useState('');
  const [otpAuthURL, setOtpAuthURL] = useState('');
  const [otpToken, setOtpToken] = useState('');
  const [verificationError, setVerificationError] = useState('');
  const [setupError, setSetupError] = useState('');
  const dispatch = useDispatch();
  const navigate = useNavigate();
  const username = useSelector((state) => state.auth.user); // Get username from Redux state
  console.log("Redux Username:", username);
  useEffect(() => {
    if (isOpen) {
      fetchMFASetupData();
    } else {
      resetDialogState();
    }
  }, [isOpen]);

  const resetDialogState = () => {
    setSecret('');
    setOtpAuthURL('');
    setOtpToken('');
    setVerificationError('');
    setSetupError('');
  };

  const fetchMFASetupData = async () => {
    try {
      const response = await apiClient.apiClientWithInterceptor.post('/api/auth/mfa/setup/');
      if (response.status === 200) {
        setSecret(response.data.secret);
        setOtpAuthURL(response.data.otpauth_url);
        setSetupError('');
      } else {
        setSetupError('Failed to fetch MFA setup data.');
      }
    } catch (error) {
      console.error('MFA Setup API Error:', error);
      setSetupError('Error fetching MFA setup data. Please try again.');
    }
  };

  const handleOtpTokenChange = (e) => setOtpToken(e.target.value);

  const handleVerifyMFA = async () => {
    setVerificationError('');
    if (!username) { // Check if username is available
      setVerificationError("Username not available. Please login or ensure user information is loaded.");
      return;
    }
    try {
      const response = await apiClient.apiClientWithInterceptor.post('/api/auth/mfa/verify/', {
        token: otpToken,
        username: username, // Use username from Redux state
        headers: { Authorization: undefined }, // <--- Override Authorization header to undefined
      });
      if (response.status === 200) {
        const { access, message } = response.data;
        dispatch(loginSuccess({ accessToken: access }));
        onClose();
        navigate('/dashboard');
      } else {
        setVerificationError('Invalid verification code. Please try again.');
      }
    } catch (error) {
      console.error('MFA Verify API Error:', error);
      if (error.response && error.response.data && error.response.data.message) {
        setVerificationError(error.response.data.message);
      } else {
        setVerificationError('Error verifying MFA. Please try again.');
      }
    }
  };

  const handleSkipMFA = () => {
    onClose();
    navigate('/dashboard');
  };

  if (!isOpen) {
    return null;
  }

  return (
    <div className="mfa-setup-dialog-overlay">
      <div className="mfa-setup-dialog">
        <h3>Set up Two-Factor Authentication</h3>
        {setupError && <div className="error-message">{setupError}</div>}
        <p>Scan the QR code below with your authenticator app or enter the secret key.</p>
        {otpAuthURL && (
          <div className="qrcode-container">
            <QRCodeCanvas value={otpAuthURL} size={256} level="H" />
          </div>
        )}
        {secret && (
          <div className="secret-key-container">
            <p>Secret Key: <strong>{secret}</strong></p>
          </div>
        )}
        <p>Enter verification code:</p>
        <input
          type="text"
          placeholder="Verification Code"
          value={otpToken}
          onChange={handleOtpTokenChange}
        />
        {verificationError && <div className="error-message">{verificationError}</div>}
        <div className="dialog-buttons">
          <button onClick={handleVerifyMFA}>Verify MFA</button>
          <button onClick={handleSkipMFA}>Skip for Now</button>
        </div>
      </div>
    </div>
  );
}

export default MFASetupDialog;
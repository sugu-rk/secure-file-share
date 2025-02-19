// src/components/auth/MFAStatus.js
import React, { useState, useEffect } from 'react';
import apiClient from '../../services/apiClient';
import MFASetupDialog from './MFASetupDialog'; // Import MFASetupDialog

function MFAStatus() {
  const [mfaStatus, setMfaStatus] = useState({ enabled: false, verified: false });
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState('');
  const [isMFASetupDialogOpen, setIsMFASetupDialogOpen] = useState(false); // State for dialog visibility

  useEffect(() => {
    fetchMFAStatus();
  }, []);

  const fetchMFAStatus = async () => {
    setIsLoading(true);
    setError('');
    try {
      const response = await apiClient.get('/api/auth/mfa/status/', true);
      if (response.status === 200) {
        setMfaStatus({
          enabled: response.data.otp_enabled,
          verified: response.data.otp_verified,
        });
      } else {
        setError('Failed to fetch MFA status.');
      }
    } catch (error) {
      console.error('Error fetching MFA status:', error);
      setError('Error fetching MFA status. Please try again.');
    } finally {
      setIsLoading(false);
    }
  };

  const handleSetupMFA = () => {
    setIsMFASetupDialogOpen(true); // Open MFA setup dialog
  };

  const handleMFADialogClose = () => {
    setIsMFASetupDialogOpen(false); // Close MFA setup dialog
    fetchMFAStatus(); // Refresh MFA status after dialog is closed (to update display)
  };

  if (isLoading) {
    return <p>Loading MFA Status...</p>;
  }

  if (error) {
    return <p className="error-message">Error: {error}</p>;
  }

  return (
    <div className="mfa-status-container">
      <p>
        Two-Factor Authentication: <strong>{mfaStatus.enabled ? 'Enabled' : 'Disabled'}</strong>
      </p>
      {!mfaStatus.enabled && (
        <button onClick={handleSetupMFA}>Setup MFA</button>
      )}
      <MFASetupDialog isOpen={isMFASetupDialogOpen} onClose={handleMFADialogClose} /> {/* Render MFA Dialog */}
    </div>
  );
}

export default MFAStatus;
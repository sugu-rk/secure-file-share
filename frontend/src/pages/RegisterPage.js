// src/pages/RegisterPage.js
import React, { useState } from 'react';
import RegisterForm from '../components/auth/RegisterForm';
import MFASetupDialog from '../components/auth/MFASetupDialog'; // Import MFASetupDialog

function RegisterPage() {
  const [isMFADialogOpen, setIsMFADialogOpen] = useState(false); // State for dialog visibility

  const handleRegistrationSuccess = () => {
    setIsMFADialogOpen(true); // Open MFA dialog after successful registration
  };

  const handleMFADialogClose = () => {
    setIsMFADialogOpen(false); // Close MFA dialog
  };

  return (
    <div>
      <h1>Register Page</h1>
      <RegisterForm onRegistrationSuccess={handleRegistrationSuccess} /> {/* Pass success handler */}
      <MFASetupDialog isOpen={isMFADialogOpen} onClose={handleMFADialogClose} /> {/* Render MFA Dialog */}
    </div>
  );
}

export default RegisterPage;
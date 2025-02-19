// File: src/pages/LandingPage.js
import React from 'react';
import { useNavigate } from 'react-router-dom';

function LandingPage() {
  const navigate = useNavigate();
  return (
    <div style={{ textAlign: 'center', marginTop: '50px' }}>
      <h1>Secure File Sharing Application</h1>
      <div style={{ marginTop: '30px' }}>
        <button onClick={() => navigate('/register')} style={{ marginRight: '20px' }}>
          Register
        </button>
        <button onClick={() => navigate('/login')} style={{ marginRight: '20px' }}>
          Login
        </button>
      </div>
    </div>
  );
}

export default LandingPage;

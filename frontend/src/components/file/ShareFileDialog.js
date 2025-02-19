// src/components/file/ShareFileDialog.js
import React, { useState } from 'react';
import apiClient from '../../services/apiClient';

function ShareFileDialog({ isOpen, onClose, fileId, onFileShared }) {
  const [sharedEmails, setSharedEmails] = useState('');
  const [permissionType, setPermissionType] = useState('view');
  const [shareError, setShareError] = useState('');
  const [shareSuccessMessage, setShareSuccessMessage] = useState('');

  const handleEmailChange = (e) => setSharedEmails(e.target.value);
  const handlePermissionChange = (e) => setPermissionType(e.target.value);

  const handleShareSubmit = async (e) => {
    e.preventDefault();
    setShareError('');
    setShareSuccessMessage('');

    if (!sharedEmails) {
      setShareError('Please enter at least one email address.');
      return;
    }

    const emailsArray = sharedEmails.split(',').map(email => email.trim()).filter(email => email);

    if (emailsArray.length === 0) {
      setShareError('Please enter valid email addresses separated by commas.');
      return;
    }

    try {
      const response = await apiClient.apiClientWithInterceptor.post('/api/file/share/', {
        file_id: fileId,
        shared_with_emails: emailsArray,
        permission_type: permissionType,
      });

      if (response.status === 201) {
        setShareSuccessMessage(response.data.message || 'File shared successfully.');
        setSharedEmails('');
        if (onFileShared) {
            console.log("ShareFileDialog.js - handleShareSubmit: Calling onFileShared callback"); // ADD THIS LOG
          onFileShared();
        }
      } else {
        setShareError(response.data.error || `File sharing failed: ${response.status} - ${response.statusText}`);
      }
    } catch (error) {
      console.error('File Share API Error:', error);
      if (error.response && error.response.data && error.response.data.error) {
        setShareError(error.response.data.error);
      } else {
        setShareError('File sharing failed. Could not connect to server.');
      }
    }
  };

  const handleCloseDialog = () => {
    onClose();
    setShareError('');
    setShareSuccessMessage('');
    setSharedEmails('');
  };

  if (!isOpen) {
    return null;
  }

  return (
    <div className="share-dialog-overlay">
      <div className="share-dialog">
        <h3>Share File</h3>
        {shareError && <div className="error-message">{shareError}</div>}
        {shareSuccessMessage && <div className="success-message">{shareSuccessMessage}</div>}

        <form onSubmit={handleShareSubmit}>
          <div>
            <label htmlFor="shared-emails">Share with (comma-separated emails):</label>
            <input
              type="text"
              id="shared-emails"
              value={sharedEmails}
              onChange={handleEmailChange}
              placeholder="user1@example.com, user2@example.com"
              required
            />
          </div>

          <div>
            <label htmlFor="permission-type">Permission Type:</label>
            <select
              id="permission-type"
              value={permissionType}
              onChange={handlePermissionChange}
            >
              <option value="view">View</option>
              <option value="download">Download</option>
              <option value="full">Full</option>
            </select>
          </div>

          <div className="dialog-buttons">
            <button type="submit">Share</button>
            <button type="button" onClick={handleCloseDialog}>Close</button>
          </div>
        </form>
      </div>
    </div>
  );
}

export default ShareFileDialog;

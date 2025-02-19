// src/components/file/ShareLinkDialog.js
import React, { useState } from 'react';
import apiClient from '../../services/apiClient';

function ShareLinkDialog({ isOpen, onClose, fileId }) {
  const [permissionType, setPermissionType] = useState('view');
  const [expirationTime, setExpirationTime] = useState('');
  const [shareableLink, setShareableLink] = useState('');
  const [linkError, setLinkError] = useState('');
  const [linkSuccessMessage, setLinkSuccessMessage] = useState('');

  const handlePermissionChange = (e) => setPermissionType(e.target.value);
  const handleExpirationTimeChange = (e) => setExpirationTime(e.target.value);

  const handleGenerateLink = async (e) => {
    e.preventDefault();
    setLinkError('');
    setLinkSuccessMessage('');
    setShareableLink('');

    try {
      const apiExpirationTime = expirationTime ? new Date(expirationTime).toISOString() : null;

      const response = await apiClient.apiClientWithInterceptor.post('/api/file/share-link/generate/', {
        file_id: fileId,
        permission_type: permissionType,
        expiration_time: apiExpirationTime,
      });

      if (response.status === 201) {
        setShareableLink(response.data.shareable_link_url);
        setLinkSuccessMessage(response.data.message || 'Shareable link generated successfully.');
      } else {
        setLinkError(response.data.error || `Link generation failed: ${response.status} - ${response.statusText}`);
      }
    } catch (error) {
      console.error('Share Link API Error:', error);
      if (error.response && error.response.data && error.response.data.error) {
        setLinkError(error.response.data.error);
      } else {
        setLinkError('Shareable link generation failed. Could not connect to server.');
      }
    }
  };

  const handleCloseDialog = () => {
    onClose();
    setLinkError('');
    setLinkSuccessMessage('');
    setShareableLink('');
    setExpirationTime('');
  };

  const handleCopyLink = () => {
    if (shareableLink) {
      navigator.clipboard.writeText(shareableLink);
      setLinkSuccessMessage('Link copied to clipboard!');
      setTimeout(() => setLinkSuccessMessage('Shareable link generated successfully. (Link copied to clipboard!)'), 3000);
    }
  };

  if (!isOpen) {
    return null;
  }

  return (
    <div className="share-link-dialog-overlay">
      <div className="share-link-dialog">
        <h3>Generate Shareable Link</h3>
        {linkError && <div className="error-message">{linkError}</div>}
        {linkSuccessMessage && <div className="success-message">{linkSuccessMessage}</div>}

        <form onSubmit={handleGenerateLink}>
          <div>
            <label htmlFor="share-link-permission-type">Permission Type:</label>
            <select
              id="share-link-permission-type"
              value={permissionType}
              onChange={handlePermissionChange}
            >
              <option value="view">View</option>
              <option value="download">Download</option>
              <option value="full">Full</option>
            </select>
          </div>

          <div>
            <label htmlFor="share-link-expiration">Expiration Time (Optional):</label>
            <input
              type="datetime-local"
              id="share-link-expiration"
              value={expirationTime}
              onChange={handleExpirationTimeChange}
              placeholder="YYYY-MM-DDTHH:mm"
            />
          </div>

          <div className="dialog-buttons">
            <button type="submit">Generate Link</button>
            <button type="button" onClick={handleCloseDialog}>Close</button>
          </div>
        </form>

        {shareableLink && (
          <div className="shareable-link-section">
            <p>Shareable Link:</p>
            <div className="link-display">
              <a href={shareableLink} target="_blank" rel="noopener noreferrer">{shareableLink}</a>
            </div>
            <button type="button" onClick={handleCopyLink}>Copy Link</button>
          </div>
        )}
      </div>
    </div>
  );
}

export default ShareLinkDialog;

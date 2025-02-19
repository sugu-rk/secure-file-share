// src/components/file/SharedByMeFileList.js
import React, { useState, useEffect, useCallback } from 'react';
import apiClient from '../../services/apiClient';
import ShareFileDialog from './ShareFileDialog';

function SharedByMeFileList() {
  const [sharedFilesByMe, setSharedFilesByMe] = useState([]);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState('');
  const [isShareDialogOpen, setIsShareDialogOpen] = useState(false);


  const fetchSharedFilesByMe = useCallback(async () => {
    setIsLoading(true);
    setError('');
    try {
      const response = await apiClient.apiClientWithInterceptor.get('/api/file/shared-by-me/');
      if (response.status === 200) {
        setSharedFilesByMe(response.data);
      } else {
        setError('Failed to load files shared by me.');
      }
    } catch (error) {
      console.error('Error fetching shared files by me:', error);
      setError('Error loading files shared by me. Please try again.');
    } finally {
      setIsLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchSharedFilesByMe();
  }, [fetchSharedFilesByMe]);
  console.log("SharedByMeFileList.js - Component Rendered"); // ADD THIS LOG

  const handleRevokeAccess = async (fileId, userEmail) => {
    setError('');
    try {
      const response = await apiClient.post('/api/file/revoke-access/', {
        file_id: fileId,
        user_email: userEmail,
      });
      if (response.status === 200) {
        fetchSharedFilesByMe();
      } else {
        setError(response.data.error || `Failed to revoke access: ${response.status} - ${response.statusText}`);
      }
    } catch (error) {
      console.error('Error revoking access:', error);
      setError('Error revoking access. Please try again.');
    }
  };

  const handleModifyPermission = async (fileId, userEmail, newPermissionType) => {
    setError('');
    try {
      const response = await apiClient.post('/api/file/modify-permission/', {
        file_id: fileId,
        user_email: userEmail,
        permission_type: newPermissionType,
      });
      if (response.status === 200) {
        fetchSharedFilesByMe();
      } else {
        setError(response.data.error || `Failed to modify permission: ${response.status} - ${response.statusText}`);
      }
    } catch (error) {
      console.error('Error modifying permission:', error);
      setError('Error modifying permission. Please try again.');
    }
  };
  const handleShareClick = () => {
    setIsShareDialogOpen(true);
  };


  if (isLoading) {
    return <p>Loading files shared by me...</p>;
  }

  if (error) {
    return <p className="error-message">{error}</p>;
  }

  if (sharedFilesByMe.length === 0) {
    return <p>You haven't shared any files yet.</p>;
  }

  return (
    <div className="shared-files-by-me-container">
      <h3>Files Shared By Me</h3>
      {/* <button onClick={handleShareClick}>Share File</button> */}
      {error && <div className="error-message">{error}</div>}
      <ul>
        {sharedFilesByMe.map((file) => (
          <li key={file.id}>
            {file.filename}
            {file.shared_with && file.shared_with.length > 0 && (
              <ul>
                {file.shared_with.map((sharedUser, index) => (
                  <li key={index} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                    <span>Shared with: {sharedUser.user_email} (Permission:
                      <select
                        value={sharedUser.permission_type}
                        onChange={(e) => handleModifyPermission(file.id, sharedUser.user_email, e.target.value)}
                        style={{ marginLeft: '5px', marginRight: '5px' }}
                      >
                        <option value="view">View</option>
                        <option value="download">Download</option>
                        <option value="full">Full</option>
                      </select>
                      )
                    </span>
                    <button onClick={() => handleRevokeAccess(file.id, sharedUser.user_email)} style={{ marginLeft: '10px' }}>Revoke</button>
                  </li>
                ))}
              </ul>
            )}
          </li>
        ))}
      </ul>
      <ShareFileDialog
        isOpen={isShareDialogOpen}
        onClose={() => setIsShareDialogOpen(false)}
        onFileShared={fetchSharedFilesByMe}
      />
    </div>
  );
}

export default SharedByMeFileList;

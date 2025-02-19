// src/components/file/SharedToMeFileList.js
import React, { useState, useEffect, useCallback } from 'react';
import apiClient from '../../services/apiClient';

function SharedToMeFileList() {
  const [sharedFilesToMe, setSharedFilesToMe] = useState([]);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState('');

  const fetchSharedFilesToMe = useCallback(async () => {
    setIsLoading(true);
    setError('');
    try {
      const response = await apiClient.apiClientWithInterceptor.get('/api/file/shared-to-me/', true);
      if (response.status === 200) {
        setSharedFilesToMe(response.data);
      } else {
        setError('Failed to load files shared with me.');
      }
    } catch (error) {
      console.error('Error fetching shared files to me:', error);
      setError('Error loading files shared with me. Please try again.');
    } finally {
      setIsLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchSharedFilesToMe();
  }, [fetchSharedFilesToMe]);

  const handleDownloadSharedFile = useCallback(async (fileId, filename, permissionType) => {
    if (permissionType !== 'view') {
      setError('');
      try {
        // Call download endpoint via apiClient with interceptors, expecting a blob.
        const response = await apiClient.get(`/api/file/download/${fileId}/`, true, 'blob');
        if (response.status === 200) {
          const url = window.URL.createObjectURL(new Blob([response.data]));
          const link = document.createElement('a');
          link.href = url;
          link.setAttribute('download', filename);
          document.body.appendChild(link);
          link.click();
          link.parentNode.removeChild(link);
        } else if (response.status === 403 || response.status === 404) {
          setError(response.data.error || `Download failed: ${response.status} - ${response.statusText}`);
        } else {
          setError(`Download failed: ${response.status} - ${response.statusText}`);
        }
      } catch (error) {
        console.error('File Download Error:', error);
        setError('Error downloading file. Please try again.');
      }
    } else {
      setError("You have only view permission for this file, download is not allowed.");
    }
  }, []);

  const handleViewFile = useCallback(async (fileId, filename) => {
    setError('');
    try {
      // Call the endpoint with ?view=true via apiClient to trigger full decryption and inline display.
      const response = await apiClient.get(`/api/file/download/${fileId}/?view=true`, true, 'blob');
      if (response.status === 200) {
        const blobUrl = window.URL.createObjectURL(response.data);
        window.open(blobUrl, '_blank');
      } else {
        setError(`Error viewing file: ${response.status} - ${response.statusText}`);
      }
    } catch (error) {
      console.error("Error viewing file:", error);
      setError('Error viewing file. Please try again.');
    }
  }, []);

  if (isLoading) {
    return <p>Loading files shared with me...</p>;
  }

  if (error) {
    return <p className="error-message">{error}</p>;
  }

  if (sharedFilesToMe.length === 0) {
    return <p>No files have been shared with you yet.</p>;
  }

  return (
    <div className="shared-files-to-me-container">
      <h3>Files Shared With Me</h3>
      {error && <div className="error-message">{error}</div>}
      <ul style={{ listStyleType: 'none', paddingLeft: 0 }}>
        {sharedFilesToMe.map((file) => (
          <li key={file.id} style={{ marginBottom: '10px', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <span>{file.filename} (Permission: {file.shared_permission_type})</span>
            <div>
              {file.shared_permission_type !== 'view' && (
                <button
                  onClick={() =>
                    handleDownloadSharedFile(file.id, file.filename, file.shared_permission_type)
                  }
                  style={{ marginLeft: '10px' }}
                >
                  Download
                </button>
              )}
              {file.shared_permission_type === 'view' && (
                <button
                  onClick={() => handleViewFile(file.id, file.filename)}
                  style={{ marginLeft: '10px' }}
                >
                  View
                </button>
              )}
            </div>
          </li>
        ))}
      </ul>
    </div>
  );
}

export default SharedToMeFileList;

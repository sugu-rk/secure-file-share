// src/components/file/FileList.js
import React, { useState, useEffect, forwardRef, useImperativeHandle, useCallback } from 'react';
import apiClient from '../../services/apiClient';
import ShareFileDialog from './ShareFileDialog';
import ShareLinkDialog from './ShareLinkDialog';

const FileList = forwardRef((props, ref) => {
  const [files, setFiles] = useState([]);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState('');
  const [isShareDialogOpen, setIsShareDialogOpen] = useState(false);
  const [selectedFileIdForSharing, setSelectedFileIdForSharing] = useState(null);
  const [isShareLinkDialogOpen, setIsShareLinkDialogOpen] = useState(false);
  const [selectedFileIdForLinkSharing, setSelectedFileIdForLinkSharing] = useState(null);

  const fetchMyFiles = useCallback(async () => {
    setIsLoading(true);
    setError('');
    try {
      const response = await apiClient.get('/api/file/my-files/', true);
      console.log("FileList.js - Files fetched:", response.data);
      if (response.status === 200) {
        setFiles(response.data);
      } else {
        setError('Failed to load file list.');
      }
    } catch (error) {
      console.error('FileList.js - Error fetching files:', error);
      setError('Error loading file list. Please try again.');
    } finally {
      setIsLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchMyFiles();
  }, [fetchMyFiles]);

  useImperativeHandle(ref, () => ({
    fetchMyFiles,
    forceFetchFiles: fetchMyFiles,
  }));

  const handleShareClick = (fileId) => {
    setSelectedFileIdForSharing(fileId);
    setIsShareDialogOpen(true);
  };

  const handleShareLinkClick = (fileId) => {
    setSelectedFileIdForLinkSharing(fileId);
    setIsShareLinkDialogOpen(true);
  };

  const handleDownload = useCallback(async (fileId, filename) => {
    setError('');
    try {
      // Call download endpoint via apiClient with interceptors and expecting a blob.
      const response = await apiClient.get(`/api/file/download/${fileId}/`, true, 'blob');
      console.log("FileList.js - Full API Download Response:", response);
      console.log("FileList.js - Response Data (before Blob check):", response.data);
      console.log("FileList.js - Response Headers:", response.headers);

      if (response.headers['content-type'] && !response.headers['content-type'].startsWith('application/octet-stream')) {
        console.error("FileList.js - Unexpected response format:", response);
        setError("Server returned an unexpected response. Please try again.");
        return;
      }

      let encryptedFileBlob = response.data;
      console.log('FileList.js - Encrypted file Blob received from server:', encryptedFileBlob);

      if (!(encryptedFileBlob instanceof Blob)) {
        encryptedFileBlob = new Blob([encryptedFileBlob], { type: response.headers['content-type'] });
      }

      // Extract key and IV from headers.
      const encryptionKeyBase64_header = response.headers['x-encryption-key'];
      const ivBase64_header = response.headers['x-iv'];
      console.log("FileList.js - Encryption Key (from header):", encryptionKeyBase64_header);
      console.log("FileList.js - IV (from header):", ivBase64_header);

      if (!encryptionKeyBase64_header || !ivBase64_header) {
        setError("Encryption key or IV missing in response.");
        return;
      }

      // Decode Base64 values.
      const decryptionKeyRaw = Uint8Array.from(atob(encryptionKeyBase64_header), c => c.charCodeAt(0));
      const iv = Uint8Array.from(atob(ivBase64_header), c => c.charCodeAt(0));
      console.log("FileList.js - Decryption Key (Uint8Array):", decryptionKeyRaw);
      console.log("FileList.js - IV (Uint8Array):", iv);

      // Import key for decryption.
      const decryptionKey = await window.crypto.subtle.importKey(
        "raw",
        decryptionKeyRaw,
        { name: "AES-CBC" },
        false,
        ["decrypt"]
      );
      console.log("FileList.js - CryptoKey Object:", decryptionKey);

      // Read the blob as an ArrayBuffer.
      const fileReader = new FileReader();
      fileReader.onload = async (event) => {
        try {
          console.log("FileList.js - Encrypted Buffer:", event.target.result);
          const decryptedBuffer = await window.crypto.subtle.decrypt(
            { name: "AES-CBC", iv: iv },
            decryptionKey,
            event.target.result
          );
          console.log("FileList.js - Decrypted Buffer:", decryptedBuffer);
          const decryptedBlob = new Blob([decryptedBuffer]);
          const downloadURL = window.URL.createObjectURL(decryptedBlob);

          // Create a temporary link to trigger the download.
          const link = document.createElement('a');
          link.href = downloadURL;
          link.setAttribute('download', filename);
          document.body.appendChild(link);
          link.click();
          link.remove();
          console.log("FileList.js - Download triggered for:", filename);
        } catch (decryptionError) {
          console.error("FileList.js - Decryption Failed:", decryptionError);
          setError('File decryption failed.');
        }
      };
      fileReader.readAsArrayBuffer(encryptedFileBlob);
    } catch (error) {
      console.error("FileList.js - Download Error:", error);
      setError('Error downloading file. Please try again.');
    }
  }, []);

  const handleViewFile = useCallback(async (fileId, filename) => {
    setError('');
    try {
      // Use the apiClient so that token refresh is handled. Fetch the file with ?view=true.
      const response = await apiClient.get(`/api/file/download/${fileId}/?view=true`, true, 'blob');
      if (response.status === 200) {
        // Create a Blob URL from the response.
        const blobUrl = window.URL.createObjectURL(response.data);
        // Open the Blob URL in a new tab.
        window.open(blobUrl, '_blank');
        console.log("FileList.js - View triggered for:", filename);
      } else {
        setError(`Error viewing file: ${response.status} - ${response.statusText}`);
      }
    } catch (error) {
      console.error("Error viewing file:", error);
      setError('Error viewing file. Please try again.');
    }
  }, []);

  if (isLoading) return <p>Loading files...</p>;
  if (error) return <p className="error-message">{error}</p>;
  if (files.length === 0) return <p>No files uploaded yet.</p>;

  return (
    <div className="file-list-container">
      <h3>My Files</h3>
      {error && <div className="error-message">{error}</div>}
      <ul style={{ listStyleType: 'none', paddingLeft: 0 }}>
        {files.map((file) => (
          <li key={file.id} style={{ marginBottom: '10px', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <span>{file.filename}</span>
            <div>
              <button onClick={() => handleShareLinkClick(file.id)} style={{ marginLeft: '10px' }}>
                ShareLink
              </button>
              <button onClick={() => handleShareClick(file.id)} style={{ marginLeft: '10px' }}>
                Share
              </button>
              <button onClick={() => handleDownload(file.id, file.filename)} style={{ marginLeft: '10px' }}>
                Download
              </button>
              <button onClick={() => handleViewFile(file.id, file.filename)} style={{ marginLeft: '10px' }}>
                View
              </button>
            </div>
          </li>
        ))}
      </ul>
      <ShareLinkDialog
        isOpen={isShareLinkDialogOpen}
        onClose={() => setIsShareLinkDialogOpen(false)}
        fileId={selectedFileIdForLinkSharing}
      />
      <ShareFileDialog
        isOpen={isShareDialogOpen}
        onClose={() => setIsShareDialogOpen(false)}
        fileId={selectedFileIdForSharing}
        onFileShared={fetchMyFiles}
      />
    </div>
  );
});

export default FileList;

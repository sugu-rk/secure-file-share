// src/components/file/FileUploadForm.js
import React, { useState } from 'react';
import apiClient from '../../services/apiClient'; // Import apiClient

function FileUploadForm({ onFileUploadSuccess }) {
    const [selectedFile, setSelectedFile] = useState(null);
    const [filename, setFilename] = useState('');
    const [uploadProgress, setUploadProgress] = useState(0);
    const [uploadError, setUploadError] = useState('');
    const [uploadSuccessMessage, setUploadSuccessMessage] = useState('');

    const handleFileChange = (event) => {
        const file = event.target.files[0];
        setSelectedFile(file);
        if (file) {
            setFilename(file.name);
        } else {
            setFilename('');
        }
    };

    const handleSubmit = async (e) => {
        e.preventDefault();
        setUploadError('');
        setUploadSuccessMessage('');
        setUploadProgress(0);

        if (!selectedFile) {
            setUploadError('Please select a file to upload.');
            return;
        }

        try {
            // 1. Generate Encryption Key (AES-CBC)
            const encryptionKey = await window.crypto.subtle.generateKey(
                { name: "AES-CBC", length: 256 },
                true,
                ["encrypt", "decrypt"]
            );
            const exportedKey = await window.crypto.subtle.exportKey("raw", encryptionKey);
            const encryptionKeyBase64 = btoa(String.fromCharCode(...new Uint8Array(exportedKey))); // Export key to base64

            // 2. Generate Initialization Vector (IV)
            const iv = window.crypto.getRandomValues(new Uint8Array(16));
            const ivBase64 = btoa(String.fromCharCode(...iv)); // IV to base64

            // 3. Read File Content as ArrayBuffer
            const fileBuffer = await selectedFile.arrayBuffer();

            // 4. Encrypt the File Content
            const encryptedFileBuffer = await window.crypto.subtle.encrypt(
                { name: 'AES-CBC', iv: iv },
                encryptionKey,
                fileBuffer
            );
            const encryptedBlob = new Blob([encryptedFileBuffer], { type: 'application/octet-stream' });

            // 5. Prepare FormData for Upload
            const formData = new FormData();
            formData.append('filename', filename);
            formData.append('file', encryptedBlob, filename); // Send Encrypted Blob
            formData.append('encryptionKey', encryptionKeyBase64); // Send encryption key (INSECURE in real app)
            formData.append('iv', ivBase64); // Send IV (INSECURE in real app)

            // 6. API Call to /api/file/upload/ using apiClient
            const response = await apiClient.post('/api/file/upload/', formData, {
                onUploadProgress: (progressEvent) => {
                    const progress = Math.round((progressEvent.loaded * 100) / progressEvent.total);
                    setUploadProgress(progress);
                },
            });

            if (response.status === 201) {
                const { id, filename: uploadedFilename } = response.data;
                setUploadSuccessMessage(`File "${uploadedFilename}" uploaded successfully! (ID: ${id})`);
                if (onFileUploadSuccess) {
                    onFileUploadSuccess();
                    console.log("FileUploadForm.js - onFileUploadSuccess callback called after upload");
                }
                setSelectedFile(null);
                setFilename('');
                setUploadProgress(0);
            } else {
                setUploadError(`File upload failed with status code: ${response.status}`);
            }

        } catch (error) {
            console.error('FileUploadForm.js - File Upload API Error:', error);
            if (error.response && error.response.data && error.response.data.error) {
                setUploadError(`File upload failed: ${error.response.data.error}`);
            } else {
                setUploadError('File upload failed. Could not connect to server.');
            }
        }
    };

    return (
        <form onSubmit={handleSubmit}>
            <h2>Upload File</h2>
            {uploadError && <div className="error-message">{uploadError}</div>}
            {uploadSuccessMessage && <div className="success-message">{uploadSuccessMessage}</div>}

            <div>
                <label htmlFor="file-input">Select File:</label>
                <input type="file" id="file-input" onChange={handleFileChange} required />
                {filename && <p>Selected file: {filename}</p>}
            </div>

            <div className="progress-bar-container">
                <progress value={uploadProgress} max="100" />
                {uploadProgress > 0 && <span>{uploadProgress}%</span>}
            </div>

            <button type="submit">Upload File</button>
            <p style={{marginTop: '10px', fontSize: '0.8em', color: 'orange'}}>
                <b>Security Note:</b> This implementation sends the encryption key and IV directly to the server, which is <b>insecure</b> for a real application. A proper key exchange or key wrapping mechanism is needed for secure key management.
            </p>
        </form>
    );
}

export default FileUploadForm;
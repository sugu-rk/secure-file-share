// src/pages/DashboardPage.js
import React, { useCallback, useRef } from 'react'; // Import useCallback, useRef
import LogoutButton from '../components/auth/LogoutButton';
import MFAStatus from '../components/auth/MFAStatus'; // Import MFAStatus
import { useSelector } from 'react-redux'; // Import useSelector
import FileUploadForm from '../components/file/FileUploadForm'; // Import FileUploadForm
import { Link } from 'react-router-dom';
import FileList from '../components/file/FileList'; // Import FileList
import SharedToMeFileList from '../components/file/SharedToMeFileList'; // Import SharedToMeFileList
import SharedByMeFileList from '../components/file/SharedByMeFileList'; // Import SharedByMeFileList

function DashboardPage() {
    const accessToken = useSelector((state) => state.auth.accessToken); // Get accessToken from Redux
  console.log("DashboardPage - Access Token from Redux:", accessToken); // <--- Add this console.log
  const fileListRef = useRef(null); // Create a ref for FileList component

  // useCallback to memoize refreshFiles function - prevents unnecessary re-renders
  const refreshFiles = useCallback(() => {
    if (fileListRef.current && fileListRef.current.fetchMyFiles) {
      fileListRef.current.fetchMyFiles(); // Call fetchMyFiles function in FileList
    }
  }, []);

  return (
    <div>
      <h1>Dashboard Page</h1>
      <p>Welcome to your dashboard! Your files will be listed here.</p>
      <MFAStatus /> {/* Render MFAStatus component */}
      <LogoutButton />
      <FileUploadForm onFileUploadSuccess={refreshFiles} />
      <FileList ref={fileListRef} />{/* Render FileUploadForm here */}
      <SharedToMeFileList /> {/* Render SharedToMeFileList */}
      <SharedByMeFileList /> {/* Render SharedByMeFileList */}

      
      <p>Welcome to your dashboard! Your files will be listed here.</p> {/* Placeholder message */}
      {/* File List component will go here later */}
    </div>
  );
}

export default DashboardPage;
# Secure File Sharing Application

This repository contains a full-stack secure file-sharing web application. The project demonstrates user authentication (JWT-based with optional MFA), file upload/download with client-side encryption (using the Web Crypto API) and server-side AES encryption, and file sharing with role-based access control.

---

## Table of Contents

- [Project Overview](#project-overview)
- [Software Requirements](#software-requirements)
- [Repository Structure](#repository-structure)
- [Installation and Setup](#installation-and-setup)
  - [Local Setup](#local-setup)
  - [Docker Compose Setup (Optional)](#docker-compose-setup-optional)
- [Usage Instructions](#usage-instructions)
  - [Frontend (Localhost:3000)](#frontend-localhost3000)
  - [Backend (Localhost:8000)](#backend-localhost8000)
- [Superuser Credentials](#superuser-credentials)
- [Application Flow](#application-flow)
- [API Endpoints Overview](#api-endpoints-overview)
- [Important Security Notes](#important-security-notes)
- [Contributing](#contributing)
- [License](#license)
- [Contact](#contact)

---

## Project Overview

This application is built to allow users to securely share files by:

- **User Authentication & Authorization:**  
  - Register, Login, Logout (JWT token–based authentication).
  - Optional Multi-factor Authentication (MFA) can be enabled later.
  - Role-based access control (RBAC):
    - **Admin:** Manage all users and files.
    - **Regular User:** Upload, download, and share files.
    - **Guest:** Limited file viewing via secure shareable links.

- **File Upload and Encryption:**  
  - Files are encrypted on the client side (using the Web Crypto API) before being uploaded.
  - The backend applies AES-256 encryption to files at rest.

- **File Sharing:**  
  - Users can share files with specific other users (assigning view or download permissions).
  - Secure shareable links (for guest access) can be generated with expiration times.

- **Debug Logging:**  
  - For development, all encryption keys and security details are logged for debugging purposes.

---

## Software Requirements

- **Frontend:**  
  - React, Redux  
  - JWT-based authentication  
  - Web Crypto API for client-side encryption

- **Backend:**  
  - Python, Django, Django REST Framework  
  - SQLite database  
  - AES-256 encryption for files  
  - JWT-based authentication with optional MFA  
  - RESTful API endpoints for user and file management

- **Other Tools:**  
  - Docker & Docker Compose (optional)

---


## Installation and Setup

### Local Setup

1. **Clone the Repository:**

   ```bash
   git clone <repository-url>
   cd secure-file-share
   ```

2. **Frontend Setup:**

   - Navigate to the `frontend` directory:

     ```bash
     cd frontend
     ```

   - Install dependencies:

     ```bash
     npm install
     ```
     or
     ```bash
     yarn install
     ```

   - Start the development server (default port **3000**):

     ```bash
     npm start
     ```
     The frontend will be available at [http://localhost:3000](http://localhost:3000).

3. **Backend Setup:**

   - Open a new terminal and navigate to the `backend` directory:

     ```bash
     cd backend
     ```

   - (Optional) Create and activate a virtual environment:

     ```bash
     python -m venv venv
     source venv/bin/activate  # On Windows: venv\Scripts\activate
     ```

   - Install backend dependencies:

     ```bash
     pip install -r requirements.txt
     ```

   - Run database migrations:

     ```bash
     python manage.py migrate
     ```

   - Start the backend server (default port **8000**):

     ```bash
     python manage.py runserver
     ```
     The backend API will be available at [http://localhost:8000](http://localhost:8000).

### Docker Compose Setup 

If you prefer to run both frontend and backend using Docker Compose, ensure Docker is installed and then run:

```bash
docker-compose up --build
```

This command will build and start both the frontend (on port 3000) and the backend (on port 8000). Adjust the `docker-compose.yml` file as needed for your environment.

---

## Usage Instructions

1. **Access the Application:**
   - Open [http://localhost:3000](http://localhost:3000) in your browser.
   - The landing page displays three buttons: **Register**, **Login**, and **Admin**.

2. **Register & Login:**
   - Click **Register** to create a new account.
   - Click **Login** to sign in.
   - (If MFA is enabled later, an "Enable MFA" button and additional MFA steps will be available.)

3. **File Operations (Post-Login):**
   - **File Upload:** Users can upload text files (encrypted on the client side).
   - **My Files:** View uploaded files, share files with other users (with permissions), generate shareable links (for guest access), and download files.
   - **Shared To Me / Shared By Me:** See files shared with you or by you along with their permissions.

4. **Logout:**  
   - Use the Logout functionality to securely end your session.

5. **Admin Placeholder:**
   - Clicking the **Admin** button navigates to an Admin page that currently displays an "Under Construction" message.

---

## Superuser Credentials

For development purposes, a superuser account is pre-created. Use the following credentials to log in as an admin:

- **Username:** `admin`
- **Password:** `admin`

*These credentials are for docker testing only.*

---

## Application Flow

1. **Clone & Setup:**  
   - Clone the repository, set up the frontend and backend (or use Docker Compose), and start the respective servers.
2. **User Authentication:**  
   - Register or log in using JWT-based authentication.  
   - Optionally, MFA can be enabled later.
3. **File Operations:**  
   - Upload files (currently, text files are fully supported).
   - Manage files: view, share, generate shareable links, and download.
4. **Role-Based Access:**  
   - Regular users manage their own files.
   - Admins can manage all users and files (admin APIs exist, but the admin page is under construction).
5. **Security Logging:**  
   - All security information, including encryption keys, is logged to the console for debugging (do not use these practices in production).

---

## API Endpoints Overview

### Authentication (Backend)
- **User Registration:** `/api/auth/register/`
- **User Login (JWT):** `/api/auth/login/`
- **Token Refresh:** `/api/auth/token/refresh/`
- **Logout:** `/api/auth/logout/`
- **MFA Setup/Verify:** `/api/auth/mfa/setup/`, `/api/auth/mfa/verify/` *(MFA can be enabled later)*

### File Management (Backend)
- **File Upload:** `/api/file/upload/`
- **My Files:** `/api/file/my-files/`
- **File Download:** `/api/file/download/<file_id>/`
- **File Sharing (between users):** `/api/file/share/`
- **Shareable Link Generation:** `/api/file/share-link/generate/`
- **Files Shared To Me:** `/api/file/shared-to-me/`
- **Files Shared By Me:** `/api/file/shared-by-me/`

### Admin (Backend – Protected Endpoints)(bckend development done)
- **Admin Dashboard Message:** `/api/file/admin-dashboard/`
- **Admin User List:** `/api/auth/admin/users/`
- **Admin Delete User:** `/api/auth/admin/user/<user_id>/`
- **Admin File List:** `/api/file/admin/files/`
- **Admin Delete File:** `/api/file/admin/file/<file_id>/`
- **Admin Audit Logs:** `/api/file/admin/audit-logs/`

*All admin endpoints require a valid access token and that the user is a superuser or belongs to the 'Admin' group.*

---

## Important Security Notes
**Note:**  
- **Encryption keys are hardcoded for the development environment.**  
- All security-related logs (including encryption key details) are printed for debugging purposes.  
- At this stage, only text files are fully supported.  
- MFA (Multi-factor Authentication) is implemented in the code but can be enabled later (an "Enable MFA" button is provided).
- Admin functionalities (user/file management, audit logs, etc.) are available via dedicated API endpoints. For now, the Admin page is a placeholder.

- **Development Only:**  
  - **Hardcoded encryption keys and debug logs** are used for the development environment only.
  - These practices **must not be used in production.**
- **Encryption:**  
  - Client-side encryption is implemented with the Web Crypto API.
  - Server-side encryption uses AES-256.
- **Authentication:**  
  - JWT token–based authentication is used.
  - MFA functionality is implemented and can be enabled later.

---



## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for more details.

---

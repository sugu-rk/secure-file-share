// src/index.js
import React from 'react';
import ReactDOM from 'react-dom/client';
import './index.css';
import AppRouter from './routes/AppRouter'; // Keep AppRouter import
import store, { persistor } from './redux/store';
import { Provider } from 'react-redux';
import { PersistGate } from 'redux-persist/integration/react';
import { BrowserRouter } from 'react-router-dom'; // Keep BrowserRouter import

const root = ReactDOM.createRoot(document.getElementById('root'));

root.render(
  <React.StrictMode>
    <Provider store={store}>
      <PersistGate
        loading={<div>Loading App...</div>} // Basic loading indicator
        persistor={persistor}
        // onBeforeLift={() => console.log("PersistGate onBeforeLift called (basic setup)")} // Optional: Basic onBeforeLift for testing - COMMENT OUT INITIALLY
      >
        <BrowserRouter>
          <AppRouter />
        </BrowserRouter>
      </PersistGate>
    </Provider>
  </React.StrictMode>
);
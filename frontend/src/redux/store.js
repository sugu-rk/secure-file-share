// src/redux/store.js
import { configureStore } from '@reduxjs/toolkit';
import authReducer from './authSlice';
import { persistStore, persistReducer } from 'redux-persist';
import storage from 'redux-persist/lib/storage';
import autoMergeLevel2 from 'redux-persist/lib/stateReconciler/autoMergeLevel2';


const persistConfig = {
  key: 'auth',
  storage,
  whitelist: ['isAuthenticated', 'accessToken', 'user'],// Persist only the 'auth' slice
  stateReconciler: autoMergeLevel2,
};

const persistedAuthReducer = persistReducer(persistConfig, authReducer);

const store = configureStore({
  reducer: {
    auth: persistedAuthReducer,
    // ... other reducers ...
  },
});

export const persistor = persistStore(store);
export default store;
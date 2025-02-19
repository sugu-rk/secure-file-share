// src/redux/authSlice.js
import { createSlice } from '@reduxjs/toolkit';

const initialState = {
  isAuthenticated: false,
  user: null,
  accessToken: null,
};

const authSlice = createSlice({
  name: 'auth',
  initialState,
  reducers: {
    loginSuccess: (state, action) => {
        console.log("loginSuccess reducer CALLED");
        console.log("Action Payload:", action.payload); // Check what is being dispatched
      
        if (!action.payload.username) {
          console.error("ERROR: Username is missing in loginSuccess action!");
        }
      
        // state.isAuthenticated = true;
        state.accessToken = action.payload.accessToken;
        if (typeof action.payload.username === "string") {
            try {
                state.user = JSON.parse(action.payload.username); // Remove extra quotes if present
            } catch (e) {
                state.user = action.payload.username || state.user; // Assign directly if it's already a valid string
            }
        }
                if (!state.user) {
            console.error("ERROR: Username is missing in loginSuccess action!");
        }

        state.isAuthenticated = true;
        console.log("State after update:", state);
      },
    logout: (state) => {
      state.isAuthenticated = false;
      state.user = null;
      state.accessToken = null;
    },
    // ... (other reducers)
  },
});

export const { loginSuccess, logout } = authSlice.actions;
export default authSlice.reducer;
// src/services/apiClient.js
import axios from 'axios';
import store from '../redux/store';

const apiClientWithInterceptor = axios.create({
    baseURL: 'http://localhost:8000',
    withCredentials: true,
    headers: {
        // 'Content-Type': 'application/json',
    },
});

// Request interceptor (as before) - ENSURE THIS CODE IS PRESENT AND UNCOMMENTED
apiClientWithInterceptor.interceptors.request.use(
    (config) => {
        const accessToken = store.getState().auth.accessToken;
        if (accessToken) {
            config.headers['Authorization'] = `Bearer ${accessToken}`;
        }
        return config;
    },
    (error) => {
        return Promise.reject(error);
    }
);

const apiClient = axios.create({
    baseURL: 'http://localhost:8000',
    withCredentials: true,
    headers: {
        // 'Content-Type': 'application/json',
    },
});


const post = async (url, data, useInterceptor = false) => { // useInterceptor defaults to false
    const client = useInterceptor ? apiClientWithInterceptor : apiClient;
    try {
        const response = await client.post(url, data);
        return response;
    } catch (error) {
        console.error('API POST request error:', error);
        throw error;
    }
};

// Modified GET function - simpler and direct responseType setting
const get = async (url, useInterceptor = false, responseType = 'json') => {
    const client = useInterceptor ? apiClientWithInterceptor : apiClient;
    try {
        const config = { responseType: responseType }; // Explicitly create config object
        if (useInterceptor && store.getState().auth.accessToken) { // Conditionally add auth header
            config.headers = { 'Authorization': `Bearer ${store.getState().auth.accessToken}` };
        }
        const response = await client.get(url, config); // Pass the config
        return response;
    } catch (error) {
        console.error('API GET request error:', error);
        throw error;
    }
};


export default {
    post,
    get,
    apiClientWithInterceptor, // Export apiClientWithInterceptor if needed for direct access
    apiClient // Export basic apiClient if needed for direct access
    // ... (rest of exports)
};
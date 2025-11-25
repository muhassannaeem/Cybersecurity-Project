// Authentication utility wired to backend API
import axios from 'axios';

const TOKEN_KEY = 'auth_token';
const USER_KEY = 'auth_user';

export const getToken = () => {
  if (typeof window === 'undefined') return null;
  return localStorage.getItem(TOKEN_KEY);
};

export const getUser = () => {
  if (typeof window === 'undefined') return null;
  const raw = localStorage.getItem(USER_KEY);
  return raw ? JSON.parse(raw) : null;
};

const setSession = (token, user) => {
  if (typeof window === 'undefined') return;
  localStorage.setItem(TOKEN_KEY, token);
  localStorage.setItem(USER_KEY, JSON.stringify(user));
  axios.defaults.headers.common['Authorization'] = `Bearer ${token}`;
};

export const initAuthFromStorage = () => {
  const token = getToken();
  if (token) {
    axios.defaults.headers.common['Authorization'] = `Bearer ${token}`;
  }
};

export const login = async (email, password) => {
  const response = await axios.post('/api/auth/login', { email, password });
  const { token, user } = response.data;
  setSession(token, user);
  return true;
};

export const logout = () => {
  if (typeof window === 'undefined') return;
  localStorage.removeItem(TOKEN_KEY);
  localStorage.removeItem(USER_KEY);
  delete axios.defaults.headers.common['Authorization'];
};

export const isAuthenticated = () => {
  return !!getToken();
};

export const signup = async (name, email, password) => {
  const response = await axios.post('/api/auth/signup', { name, email, password });
  const { token, user } = response.data;
  setSession(token, user);
  return true;
};

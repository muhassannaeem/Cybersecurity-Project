// Simple authentication utility for the cybersecurity system

export const login = (email, password) => {
  // Temporary authentication for testing
  if (email === 'test@mail.com' && password === 'test123') {
    // In a real app, you would store a token in localStorage or a cookie
    localStorage.setItem('isAuthenticated', 'true');
    return true;
  }
  return false;
};

export const logout = () => {
  localStorage.removeItem('isAuthenticated');
};

export const isAuthenticated = () => {
  // In a real app, you would check for a valid token
  return localStorage.getItem('isAuthenticated') === 'true';
};

export const signup = (name, email, password) => {
  // In a real app, you would send this data to your backend
  // For now, we'll just return true to simulate successful signup
  return true;
};
import { useState, useEffect } from 'react';
import { useRouter } from 'next/router';
import { Lock, Mail, User, Shield } from 'lucide-react';
import { signup, isAuthenticated } from '../utils/auth';
import toast from 'react-hot-toast';
import styles from './Dashboard.module.css';

export default function Signup() {
  const [name, setName] = useState('');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [error, setError] = useState('');
  const [success, setSuccess] = useState(false);
  const router = useRouter();

  // Redirect to dashboard if already authenticated
  useEffect(() => {
    if (isAuthenticated()) {
      router.push('/dashboard');
    }
  }, []);

  const handleSubmit = async (e) => {
    e.preventDefault();
    
    // Simple validation
    if (password !== confirmPassword) {
      setError('Passwords do not match');
      return;
    }
    
    if (password.length < 6) {
      setError('Password must be at least 6 characters');
      return;
    }
    
    try {
      await signup(name, email, password);
      setSuccess(true);
      setError('');
      
      // Redirect to dashboard after 2 seconds (user is already logged in)
      setTimeout(() => {
        router.push('/dashboard');
      }, 2000);
    } catch (err) {
      console.error(err);
      setError('Failed to create account');
      toast.error('Signup failed');
    }
  };

  const handleLoginRedirect = (e) => {
    e.preventDefault();
    router.push('/login');
  };

  return (
    <div className={styles.wrapper}>
      <div className={styles.maxWidthWrapper}>
        <div style={{ 
          minHeight: '100vh', 
          display: 'flex', 
          flexDirection: 'column', 
          justifyContent: 'center', 
          alignItems: 'center',
          padding: '1rem'
        }}>
          <div className={`${styles.card} glass`} style={{ 
            width: '100%', 
            maxWidth: '400px',
            padding: '2rem',
            textAlign: 'center'
          }}>
            <div style={{ 
              display: 'flex', 
              justifyContent: 'center', 
              marginBottom: '1.5rem' 
            }}>
              <Shield style={{ 
                height: '3rem', 
                width: '3rem', 
                color: 'var(--color-primary)' 
              }} />
            </div>
            
            <h1 style={{ 
              fontSize: '1.5rem', 
              fontWeight: 700, 
              color: 'var(--text-primary)',
              marginBottom: '2rem'
            }}>
              Cybersecurity System
            </h1>
            
            <h2 style={{ 
              fontSize: '1.25rem', 
              fontWeight: 600, 
              color: 'var(--text-primary)',
              marginBottom: '1.5rem'
            }}>
              Create a new account
            </h2>
            
            {error && (
              <div style={{
                backgroundColor: 'var(--color-danger-bg)',
                color: 'var(--color-danger-text)',
                padding: '0.75rem',
                borderRadius: '0.5rem',
                marginBottom: '1rem',
                fontSize: '0.875rem'
              }}>
                {error}
              </div>
            )}
            
            {success && (
              <div style={{
                backgroundColor: 'var(--color-success-bg)',
                color: 'var(--color-success-text)',
                padding: '0.75rem',
                borderRadius: '0.5rem',
                marginBottom: '1rem',
                fontSize: '0.875rem'
              }}>
                Account created successfully! Redirecting to login...
              </div>
            )}
            
            <form onSubmit={handleSubmit}>
              <div style={{ marginBottom: '1.5rem' }}>
                <label 
                  htmlFor="name" 
                  style={{ 
                    display: 'block', 
                    textAlign: 'left', 
                    marginBottom: '0.5rem', 
                    fontSize: '0.875rem',
                    fontWeight: 500,
                    color: 'var(--text-secondary)'
                  }}
                >
                  Full name
                </label>
                <div className="relative">
                  <div style={{ 
                    position: 'absolute', 
                    left: '0.75rem', 
                    top: '50%', 
                    transform: 'translateY(-50%)',
                    color: 'var(--text-secondary)'
                  }}>
                    <User size={18} />
                  </div>
                  <input
                    id="name"
                    name="name"
                    type="text"
                    autoComplete="name"
                    required
                    value={name}
                    onChange={(e) => setName(e.target.value)}
                    style={{
                      width: '100%',
                      paddingLeft: '2.5rem',
                      paddingRight: '0.75rem',
                      paddingTop: '0.75rem',
                      paddingBottom: '0.75rem',
                      borderRadius: '0.5rem',
                      border: '1px solid var(--border-color)',
                      backgroundColor: 'var(--card-background)',
                      color: 'var(--text-primary)',
                      fontSize: '0.875rem',
                      transition: 'border-color 0.3s ease'
                    }}
                    placeholder="John Doe"
                  />
                </div>
              </div>
              
              <div style={{ marginBottom: '1.5rem' }}>
                <label 
                  htmlFor="email" 
                  style={{ 
                    display: 'block', 
                    textAlign: 'left', 
                    marginBottom: '0.5rem', 
                    fontSize: '0.875rem',
                    fontWeight: 500,
                    color: 'var(--text-secondary)'
                  }}
                >
                  Email address
                </label>
                <div className="relative">
                  <div style={{ 
                    position: 'absolute', 
                    left: '0.75rem', 
                    top: '50%', 
                    transform: 'translateY(-50%)',
                    color: 'var(--text-secondary)'
                  }}>
                    <Mail size={18} />
                  </div>
                  <input
                    id="email"
                    name="email"
                    type="email"
                    autoComplete="email"
                    required
                    value={email}
                    onChange={(e) => setEmail(e.target.value)}
                    style={{
                      width: '100%',
                      paddingLeft: '2.5rem',
                      paddingRight: '0.75rem',
                      paddingTop: '0.75rem',
                      paddingBottom: '0.75rem',
                      borderRadius: '0.5rem',
                      border: '1px solid var(--border-color)',
                      backgroundColor: 'var(--card-background)',
                      color: 'var(--text-primary)',
                      fontSize: '0.875rem',
                      transition: 'border-color 0.3s ease'
                    }}
                    placeholder="you@example.com"
                  />
                </div>
              </div>

              <div style={{ marginBottom: '1.5rem' }}>
                <label 
                  htmlFor="password" 
                  style={{ 
                    display: 'block', 
                    textAlign: 'left', 
                    marginBottom: '0.5rem', 
                    fontSize: '0.875rem',
                    fontWeight: 500,
                    color: 'var(--text-secondary)'
                  }}
                >
                  Password
                </label>
                <div className="relative">
                  <div style={{ 
                    position: 'absolute', 
                    left: '0.75rem', 
                    top: '50%', 
                    transform: 'translateY(-50%)',
                    color: 'var(--text-secondary)'
                  }}>
                    <Lock size={18} />
                  </div>
                  <input
                    id="password"
                    name="password"
                    type="password"
                    autoComplete="new-password"
                    required
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    style={{
                      width: '100%',
                      paddingLeft: '2.5rem',
                      paddingRight: '0.75rem',
                      paddingTop: '0.75rem',
                      paddingBottom: '0.75rem',
                      borderRadius: '0.5rem',
                      border: '1px solid var(--border-color)',
                      backgroundColor: 'var(--card-background)',
                      color: 'var(--text-primary)',
                      fontSize: '0.875rem',
                      transition: 'border-color 0.3s ease'
                    }}
                    placeholder="At least 6 characters"
                  />
                </div>
              </div>
              
              <div style={{ marginBottom: '1.5rem' }}>
                <label 
                  htmlFor="confirmPassword" 
                  style={{ 
                    display: 'block', 
                    textAlign: 'left', 
                    marginBottom: '0.5rem', 
                    fontSize: '0.875rem',
                    fontWeight: 500,
                    color: 'var(--text-secondary)'
                  }}
                >
                  Confirm Password
                </label>
                <div className="relative">
                  <div style={{ 
                    position: 'absolute', 
                    left: '0.75rem', 
                    top: '50%', 
                    transform: 'translateY(-50%)',
                    color: 'var(--text-secondary)'
                  }}>
                    <Lock size={18} />
                  </div>
                  <input
                    id="confirmPassword"
                    name="confirmPassword"
                    type="password"
                    autoComplete="new-password"
                    required
                    value={confirmPassword}
                    onChange={(e) => setConfirmPassword(e.target.value)}
                    style={{
                      width: '100%',
                      paddingLeft: '2.5rem',
                      paddingRight: '0.75rem',
                      paddingTop: '0.75rem',
                      paddingBottom: '0.75rem',
                      borderRadius: '0.5rem',
                      border: '1px solid var(--border-color)',
                      backgroundColor: 'var(--card-background)',
                      color: 'var(--text-primary)',
                      fontSize: '0.875rem',
                      transition: 'border-color 0.3s ease'
                    }}
                    placeholder="Confirm your password"
                  />
                </div>
              </div>

              <button
                type="submit"
                className={styles.btnPrimary}
                style={{
                  width: '100%',
                  padding: '0.75rem',
                  fontSize: '0.875rem',
                  fontWeight: 500
                }}
              >
                Create account
              </button>
            </form>
            
            <div style={{ 
              marginTop: '1.5rem', 
              textAlign: 'center', 
              fontSize: '0.875rem',
              color: 'var(--text-secondary)'
            }}>
              <p>
                Already have an account?{' '}
                <a 
                  href="#"
                  onClick={handleLoginRedirect}
                  style={{ 
                    color: 'var(--color-primary)', 
                    textDecoration: 'none',
                    fontWeight: 500
                  }}
                >
                  Sign in
                </a>
              </p>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
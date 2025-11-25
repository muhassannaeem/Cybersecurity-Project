import { useState, useEffect } from 'react';
import { useRouter } from 'next/router';
import { Lock, Mail, Shield } from 'lucide-react';
import { login, isAuthenticated } from '../utils/auth';
import toast from 'react-hot-toast';
import styles from './Dashboard.module.css';

export default function Login() {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const router = useRouter();

  // Redirect to dashboard if already authenticated
  useEffect(() => {
    if (isAuthenticated()) {
      router.push('/dashboard');
    }
  }, []);

  const handleSubmit = async (e) => {
    e.preventDefault();
    
    try {
      await login(email, password);
      router.push('/dashboard');
    } catch (err) {
      console.error(err);
      setError('Invalid email or password');
      toast.error('Login failed');
    }
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
              Sign in to your account
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
            
            <form onSubmit={handleSubmit}>
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
                    placeholder="test@mail.com"
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
                    autoComplete="current-password"
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
                    placeholder="test123"
                  />
                </div>
              </div>

              <div style={{ 
                display: 'flex', 
                justifyContent: 'space-between', 
                alignItems: 'center',
                marginBottom: '1.5rem'
              }}>
                <div style={{ display: 'flex', alignItems: 'center' }}>
                  <input
                    id="remember-me"
                    name="remember-me"
                    type="checkbox"
                    style={{ 
                      height: '1rem', 
                      width: '1rem', 
                      borderRadius: '0.25rem',
                      border: '1px solid var(--border-color)',
                      color: 'var(--color-primary)',
                      marginRight: '0.5rem'
                    }}
                  />
                  <label 
                    htmlFor="remember-me" 
                    style={{ 
                      fontSize: '0.875rem',
                      color: 'var(--text-secondary)'
                    }}
                  >
                    Remember me
                  </label>
                </div>

                <div className="text-sm">
                  <a 
                    href="#" 
                    style={{ 
                      fontSize: '0.875rem',
                      color: 'var(--color-primary)',
                      textDecoration: 'none'
                    }}
                  >
                    Forgot password?
                  </a>
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
                Sign in
              </button>
            </form>
            
            <div style={{ 
              marginTop: '1.5rem', 
              textAlign: 'center', 
              fontSize: '0.875rem',
              color: 'var(--text-secondary)'
            }}>
              <p>
                Don't have an account?{' '}
                <a 
                  href="/signup" 
                  style={{ 
                    color: 'var(--color-primary)', 
                    textDecoration: 'none',
                    fontWeight: 500
                  }}
                >
                  Sign up
                </a>
              </p>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
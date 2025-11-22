import { useEffect } from 'react';
import { useRouter } from 'next/router';
import { isAuthenticated } from '../utils/auth';

export default function Home() {
  const router = useRouter();

  useEffect(() => {
    // Check if user is authenticated
    if (isAuthenticated()) {
      // Redirect to dashboard if already logged in
      router.push('/dashboard');
    } else {
      // Redirect to login page
      router.push('/login');
    }
  }, []);

  // Show nothing while redirecting
  return null;
}
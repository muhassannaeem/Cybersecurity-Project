import type { AppProps } from 'next/app';
import { QueryClient, QueryClientProvider } from 'react-query';
import { Toaster } from 'react-hot-toast';
import '../styles/globals.css';
import { useEffect } from 'react';
import { initAuthFromStorage } from '../utils/auth';

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      refetchOnWindowFocus: false,
      retry: 1,
      staleTime: 5 * 60 * 1000, // 5 minutes
      cacheTime: 10 * 60 * 1000, // 10 minutes
    },
  },
});

export default function App({ Component, pageProps }: AppProps) {
  useEffect(() => {
    initAuthFromStorage();
  }, []);

  return (
    <QueryClientProvider client={queryClient}>
      <Component {...pageProps} />
      <Toaster
        position="top-right"
        gutter={8}
        containerClassName="toast-container"
        toastOptions={{
          duration: 4000,
          style: {
            background: 'rgba(31, 41, 55, 0.95)',
            color: '#f8fafc',
            border: '1px solid rgba(0, 212, 255, 0.3)',
            borderRadius: '12px',
            backdropFilter: 'blur(20px)',
            boxShadow: '0 8px 32px rgba(0, 0, 0, 0.3), 0 0 20px rgba(0, 212, 255, 0.1)',
            padding: '16px 20px',
            fontSize: '14px',
            fontWeight: '500',
            minWidth: '300px',
          },
          success: {
            style: {
              border: '1px solid rgba(46, 213, 115, 0.3)',
              boxShadow: '0 8px 32px rgba(0, 0, 0, 0.3), 0 0 20px rgba(46, 213, 115, 0.1)',
            },
            iconTheme: {
              primary: '#2ed573',
              secondary: 'rgba(31, 41, 55, 0.95)',
            },
          },
          error: {
            style: {
              border: '1px solid rgba(255, 71, 87, 0.3)',
              boxShadow: '0 8px 32px rgba(0, 0, 0, 0.3), 0 0 20px rgba(255, 71, 87, 0.1)',
            },
            iconTheme: {
              primary: '#ff4757',
              secondary: 'rgba(31, 41, 55, 0.95)',
            },
          },
          loading: {
            style: {
              border: '1px solid rgba(139, 92, 246, 0.3)',
              boxShadow: '0 8px 32px rgba(0, 0, 0, 0.3), 0 0 20px rgba(139, 92, 246, 0.1)',
            },
            iconTheme: {
              primary: '#8b5cf6',
              secondary: 'rgba(31, 41, 55, 0.95)',
            },
          },
        }}
      />
      
      {/* Global Performance Monitor */}
      <div 
        id="performance-indicator" 
        className="fixed bottom-4 right-4 z-50 opacity-80 hover:opacity-100 transition-opacity duration-300"
        style={{
          background: 'rgba(31, 41, 55, 0.9)',
          backdropFilter: 'blur(20px)',
          border: '1px solid rgba(0, 212, 255, 0.2)',
          borderRadius: '8px',
          padding: '8px 12px',
          fontSize: '12px',
          fontFamily: 'JetBrains Mono, monospace',
          color: '#00d4ff',
          pointerEvents: 'none',
        }}
      >
        <div className="flex items-center space-x-2">
          <div className="w-2 h-2 bg-green-400 rounded-full animate-pulse"></div>
          <span>SYSTEM OPERATIONAL</span>
        </div>
      </div>
    </QueryClientProvider>
  );
}
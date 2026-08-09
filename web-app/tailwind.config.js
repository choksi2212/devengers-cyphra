/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        primary: {
          50: '#f0f9ff',
          100: '#e0f2fe',
          200: '#bae6fd',
          300: '#7dd3fc',
          400: '#38bdf8',
          500: '#0ea5e9',
          600: '#0284c7',
          700: '#0369a1',
          800: '#075985',
          900: '#0c4a6e',
          950: '#082f49',
        },
        cyphra: {
          bg: '#0a0f1a',
          surface: '#111827',
          'surface-alt': '#0f172a',
          border: '#1e293b',
          'border-light': '#334155',
          'text-primary': '#f1f5f9',
          'text-secondary': '#94a3b8',
          'text-muted': '#64748b',
          accent: '#0ea5e9',
          'accent-hover': '#0284c7',
          'accent-muted': 'rgba(14, 165, 233, 0.1)',
          cyan: '#06b6d4',
          teal: '#14b8a6',
          success: '#10b981',
          'success-muted': 'rgba(16, 185, 129, 0.1)',
          danger: '#ef4444',
          'danger-muted': 'rgba(239, 68, 68, 0.1)',
          warning: '#f59e0b',
          'warning-muted': 'rgba(245, 158, 11, 0.1)',
        },
      },
      fontFamily: {
        sans: ['Nippo', 'sans-serif'],
        mono: ['JetBrains Mono', 'Consolas', 'monospace'],
      },
      animation: {
        'pulse-slow': 'pulse 3s cubic-bezier(0.4, 0, 0.6, 1) infinite',
        'fade-in': 'fadeIn 0.5s ease-out',
        'slide-up': 'slideUp 0.4s ease-out',
        'slide-down': 'slideDown 0.4s ease-out',
        'slide-in-left': 'slideInLeft 0.3s ease-out',
        'glow': 'glow 2s ease-in-out infinite alternate',
      },
      keyframes: {
        fadeIn: {
          '0%': { opacity: '0' },
          '100%': { opacity: '1' },
        },
        slideUp: {
          '0%': { transform: 'translateY(12px)', opacity: '0' },
          '100%': { transform: 'translateY(0)', opacity: '1' },
        },
        slideDown: {
          '0%': { transform: 'translateY(-12px)', opacity: '0' },
          '100%': { transform: 'translateY(0)', opacity: '1' },
        },
        slideInLeft: {
          '0%': { transform: 'translateX(-12px)', opacity: '0' },
          '100%': { transform: 'translateX(0)', opacity: '1' },
        },
        glow: {
          '0%': { boxShadow: '0 0 5px rgba(14, 165, 233, 0.2)' },
          '100%': { boxShadow: '0 0 20px rgba(14, 165, 233, 0.4)' },
        },
      },
    },
  },
  plugins: [],
}


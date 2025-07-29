/** @type {import('tailwindcss').Config} */
export default {
  darkMode: 'class',
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        // 深色主题科技感配色
        background: 'hsl(var(--background))',
        foreground: 'hsl(var(--foreground))',
        primary: {
          DEFAULT: '#3b82f6', // 科技蓝
          foreground: '#ffffff',
        },
        secondary: {
          DEFAULT: '#10b981', // 科技绿
          foreground: '#ffffff',
        },
        accent: {
          DEFAULT: '#06b6d4', // 青色
          foreground: '#ffffff',
        },
        muted: {
          DEFAULT: '#1f2937',
          foreground: '#9ca3af',
        },
        card: {
          DEFAULT: '#111827',
          foreground: '#f9fafb',
        },
        border: '#374151',
        input: '#374151',
        ring: '#3b82f6',
        success: '#10b981',
        warning: '#f59e0b',
        destructive: '#ef4444',
      },
      fontFamily: {
        mono: ['JetBrains Mono', 'Consolas', 'Monaco', 'monospace'],
      },
      animation: {
        'pulse-slow': 'pulse 3s cubic-bezier(0.4, 0, 0.6, 1) infinite',
        'glow': 'glow 2s ease-in-out infinite alternate',
      },
      keyframes: {
        glow: {
          '0%': { boxShadow: '0 0 5px rgba(59, 130, 246, 0.3)' },
          '100%': { boxShadow: '0 0 20px rgba(59, 130, 246, 0.6)' },
        },
      },
    },
  },
  plugins: [],
}
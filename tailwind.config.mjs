/** @type {import('tailwindcss').Config} */
export default {
  content: ['./src/**/*.{astro,html,js,jsx,md,mdx,svelte,ts,tsx,vue}'],
  theme: {
    extend: {
      colors: {
        bg: {
          DEFAULT: '#0a0f1e',
          alt: '#0f1629',
          card: '#111827',
        },
        primary: {
          DEFAULT: '#1e40af',
          hover: '#1d4ed8',
          light: '#2563eb',
        },
        accent: {
          DEFAULT: '#3b82f6',
          hover: '#60a5fa',
          glow: 'rgba(59,130,246,0.4)',
        },
        text: {
          DEFAULT: '#e2e8f0',
          muted: '#94a3b8',
          faint: '#64748b',
        },
        border: {
          DEFAULT: 'rgba(59,130,246,0.12)',
          strong: 'rgba(59,130,246,0.25)',
        },
        status: {
          community: '#6b7280',
          verified: '#d97706',
          manufacturer: '#3b82f6',
          certified: '#10b981',
        },
      },
      fontFamily: {
        display: ['"Crimson Pro"', 'Georgia', 'serif'],
        sans: ['"IBM Plex Sans"', 'system-ui', 'sans-serif'],
        mono: ['"IBM Plex Mono"', 'monospace'],
      },
      animation: {
        'fade-in': 'fadeIn 0.6s ease-out forwards',
        'slide-up': 'slideUp 0.5s ease-out forwards',
        'pulse-slow': 'pulse 4s cubic-bezier(0.4,0,0.6,1) infinite',
      },
      keyframes: {
        fadeIn: {
          '0%': { opacity: '0', transform: 'translateY(12px)' },
          '100%': { opacity: '1', transform: 'translateY(0)' },
        },
        slideUp: {
          '0%': { opacity: '0', transform: 'translateY(20px)' },
          '100%': { opacity: '1', transform: 'translateY(0)' },
        },
      },
      backgroundImage: {
        'grid-pattern': `linear-gradient(rgba(59,130,246,0.04) 1px, transparent 1px),
          linear-gradient(90deg, rgba(59,130,246,0.04) 1px, transparent 1px)`,
        'hero-glow': 'radial-gradient(ellipse 80% 50% at 50% -10%, rgba(30,64,175,0.35), transparent)',
        'blue-glow': 'radial-gradient(circle at center, rgba(59,130,246,0.15), transparent 70%)',
      },
      backgroundSize: {
        'grid': '48px 48px',
      },
    },
  },
  plugins: [],
};

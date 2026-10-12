import typography from '@tailwindcss/typography';

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
      // `prose`, used by the long documents under /bounded-embodiment/, in the site's colours.
      typography: ({ theme }) => ({
        DEFAULT: {
          css: {
            '--tw-prose-body': theme('colors.text.muted'),
            '--tw-prose-headings': theme('colors.text.DEFAULT'),
            '--tw-prose-lead': theme('colors.text.muted'),
            '--tw-prose-links': theme('colors.accent.DEFAULT'),
            '--tw-prose-bold': theme('colors.text.DEFAULT'),
            '--tw-prose-counters': theme('colors.text.faint'),
            '--tw-prose-bullets': theme('colors.text.faint'),
            '--tw-prose-hr': theme('colors.border.strong'),
            '--tw-prose-quotes': theme('colors.text.DEFAULT'),
            '--tw-prose-quote-borders': theme('colors.border.strong'),
            '--tw-prose-captions': theme('colors.text.faint'),
            '--tw-prose-code': theme('colors.text.DEFAULT'),
            '--tw-prose-pre-code': theme('colors.text.DEFAULT'),
            '--tw-prose-pre-bg': theme('colors.bg.card'),
            '--tw-prose-th-borders': theme('colors.border.strong'),
            '--tw-prose-td-borders': theme('colors.border.DEFAULT'),
            'h1, h2, h3, h4': { fontFamily: theme('fontFamily.display').join(', '), scrollMarginTop: '7rem' },
            a: { textDecoration: 'none', '&:hover': { textDecoration: 'underline' } },
            code: {
              fontWeight: '400',
              backgroundColor: 'rgba(255, 255, 255, 0.05)',
              borderRadius: '0.25rem',
              padding: '0.1em 0.3em',
              overflowWrap: 'anywhere',
            },
            'code::before': { content: 'none' },
            'code::after': { content: 'none' },
            'pre code': { overflowWrap: 'normal' },
            pre: { border: `1px solid ${theme('colors.border.DEFAULT')}` },
            // Wide tables scroll inside the column instead of widening the page; code in a cell
            // keeps its identifiers whole, so a table of them scrolls rather than squeezes.
            table: { display: 'block', overflowX: 'auto' },
            'th, td': { verticalAlign: 'top' },
            'th code, td code': { overflowWrap: 'normal' },
          },
        },
      }),
    },
  },
  plugins: [typography],
};

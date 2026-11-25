import type { Config } from 'tailwindcss'

export default {
  content: ['./index.html', './src/**/*.{ts,tsx}'],
  theme: {
    extend: {
      colors: {
        bg: {
          base: '#090909',
          secondary: '#0D0D0F',
          surface: '#111113',
          elevated: '#161619',
          hover: '#1C1C20',
        },
        border: {
          DEFAULT: '#242428',
          subtle: '#1B1B1F',
        },
        text: {
          primary: '#F5F5F5',
          secondary: '#A1A1AA',
          muted: '#71717A',
          dim: '#52525B',
        },
        accent: {
          DEFAULT: 'var(--color-accent)',
          hover: 'var(--color-accent)',
          muted: 'rgba(var(--color-accent-rgb), 0.15)',
          subtle: 'rgba(var(--color-accent-rgb), 0.06)',
        },
        green: '#36B37E',
        severity: {
          critical: '#EF4444',
          high: '#EA580C',
          medium: '#E5A93D',
          low: '#36B37E',
          info: '#60A5FA',
        },
        status: {
          open: '#71717A',
          confirmed: '#EF4444',
          in_remediation: '#E5A93D',
          accepted_risk: '#8B5CF6',
          resolved: '#36B37E',
          false_positive: '#3a3a44',
        },
      },
      fontFamily: {
        sans: ['"DM Sans"', 'system-ui', '-apple-system', 'sans-serif'],
        display: ['"Space Grotesk"', '"DM Sans"', 'system-ui', '-apple-system', 'sans-serif'],
        mono: ['"JetBrains Mono"', '"Fira Code"', 'Consolas', 'monospace'],
      },
      borderRadius: {
        sm: '4px',
        md: '7px',
        lg: '10px',
        xl: '14px',
      },
    },
  },
  plugins: [],
} satisfies Config

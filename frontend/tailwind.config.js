/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  darkMode: 'class',
  theme: {
    extend: {
      colors: {
        cyber: {
          bg:       '#080b12',
          surface:  '#0d1117',
          border:   'rgba(255,255,255,0.07)',
          red:      '#ff3860',
          cyan:     '#00e5ff',
          purple:   '#7c3aed',
          green:    '#06d6a0',
          yellow:   '#ffd166',
          orange:   '#ff8c42',
        }
      },
      fontFamily: {
        mono: ['Fira Code', 'JetBrains Mono', 'monospace'],
      },
    },
  },
  plugins: [],
}

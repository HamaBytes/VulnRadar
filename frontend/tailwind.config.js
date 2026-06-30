/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {},
  },
  plugins: [],
  spacing: {
    'gutter': '16px',
    'max-width': '1440px',
    'margin-mobile': '16px',
    'unit': '4px',
    'margin-desktop': '32px',
  }
}

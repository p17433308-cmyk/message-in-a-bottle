// Benign application code (same-origin, low entropy).
export const APP = 'acme-bank';
export function boot() {
  document.title = 'Acme Bank';
}
console.log('app booted');

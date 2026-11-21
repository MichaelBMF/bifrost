// Pairing countdown and copy button. No external requests.
(() => {
  const qr = document.querySelector('.qr[data-expires]');
  if (qr) {
    const end = Number(qr.dataset.expires) * 1000;
    const label = document.querySelector('[data-countdown]');
    const row = label && label.parentElement;
    const tick = () => {
      const left = Math.max(0, Math.round((end - Date.now()) / 1000));
      if (label) label.textContent = left > 0
        ? `noch ${Math.floor(left / 60)}:${String(left % 60).padStart(2, '0')} min`
        : 'Code abgelaufen, bitte neu erzeugen';
      if (row) row.classList.toggle('late', left < 60);
      if (left === 0) { qr.classList.add('expired'); return; }
      setTimeout(tick, 1000);
    };
    tick();
  }
  document.querySelectorAll('[data-copy]').forEach((btn) => {
    btn.addEventListener('click', async () => {
      const input = document.getElementById(btn.dataset.copy);
      try { await navigator.clipboard.writeText(input.value); } catch { input.select(); document.execCommand('copy'); }
      btn.textContent = 'Kopiert';
      setTimeout(() => { btn.textContent = 'Kopieren'; }, 1500);
    });
  });
})();

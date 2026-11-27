const panel = document.getElementById('panel');
const uploadForm = document.getElementById('uploadForm');
const csrf = document.querySelector('meta[name="csrf-token"]').content;
let selected = 0;

async function refresh() {
  try {
    const response = await fetch('/live/panel?device=' + selected);
    if (response.redirected) { window.location.href = response.url; return; }
    if (response.ok) panel.innerHTML = await response.text();
  } catch (error) {
    console.warn('Raqib server is not reachable', error);
  }
}

async function send(url, data) {
  await fetch(url, { method: 'POST', headers: { 'X-CSRF-Token': csrf }, body: new URLSearchParams(data) });
  refresh();
}

if (panel) {
  setInterval(refresh, 1000);
  panel.addEventListener('click', (event) => {
    const card = event.target.closest('[data-device]');
    if (!card) return;
    selected = Number(card.dataset.device);
    refresh();
  });
  const runButton = document.querySelector('[data-toggle-run]');
  runButton.addEventListener('click', () => {
    const run = runButton.dataset.running !== '1';
    runButton.dataset.running = run ? '1' : '0';
    runButton.textContent = run ? 'إيقاف مؤقت' : 'تشغيل';
    send('/api/control', { running: run ? '1' : '0' });
  });
  for (const id of ['speed', 'policy', 'sensitivity']) {
    document.getElementById(id).addEventListener('change', (event) => send('/api/control', { [id]: event.target.value }));
  }
  document.getElementById('auto').addEventListener('change', (event) => send('/api/control', { auto: event.target.checked ? '1' : '0' }));
  document.querySelector('[data-reset]').addEventListener('click', () => send('/api/reset', {}));
  document.querySelector('[data-stop]').addEventListener('click', () => send('/api/stop', {}));
  const attackForm = document.getElementById('attackForm');
  attackForm.addEventListener('submit', (event) => {
    event.preventDefault();
    selected = Number(attackForm.elements.device.value);
    send('/api/attack', new FormData(attackForm));
  });
}

if (uploadForm) {
  uploadForm.addEventListener('submit', () => {
    document.getElementById('busy').hidden = false;
    uploadForm.querySelector('button[type="submit"]').disabled = true;
  });
}

document.addEventListener('click', (event) => {
  const button = event.target.closest('[data-confirm]');
  if (button && !window.confirm(button.dataset.confirm)) event.preventDefault();
});

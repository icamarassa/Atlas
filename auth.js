(() => {
  const tokenKey = 'atlas-ti-admin-token';
  const path = location.pathname.toLowerCase();
  if (path.endsWith('/login.html')) {
    if (sessionStorage.getItem(tokenKey)) fetch('/api/me', { headers: { Authorization: `Bearer ${sessionStorage.getItem(tokenKey)}` } })
      .then(response => { if (response.ok) location.replace('./index.html'); else sessionStorage.removeItem(tokenKey); });
    return;
  }
  document.documentElement.classList.add('auth-check');
  const token = sessionStorage.getItem(tokenKey);
  if (!token) { location.replace('./login.html'); return; }
  fetch('/api/me', { headers: { Authorization: `Bearer ${token}` } })
    .then(response => { if (!response.ok) throw new Error('Sessão encerrada'); return response.json(); })
    .then(async user => {
      try {
        const profileResponse = await fetch('/api/me/profile', { headers: { Authorization: `Bearer ${token}` } });
        if (profileResponse.ok) {
          const profile = await profileResponse.json();
          user.directoryProfile = profile;
          const attributes = profile.attributes || {};
          user.name = attributes.displayName || [attributes.givenName, attributes.sn].filter(Boolean).join(' ') || user.name;
          user.email = attributes.mail || user.email;
        }
      } catch { /* O login continua disponível quando a consulta do perfil não responde. */ }
      sessionStorage.setItem('atlas-ti-current-user', JSON.stringify(user));
      document.documentElement.classList.remove('auth-check');
      document.dispatchEvent(new CustomEvent('atlas-authenticated', { detail: user }));
    })
    .catch(() => { sessionStorage.removeItem(tokenKey); sessionStorage.removeItem('atlas-ti-current-user'); location.replace('./login.html'); });
  document.addEventListener('click', event => {
    if (event.target.closest('[data-logout]')) {
      sessionStorage.removeItem(tokenKey);
      sessionStorage.removeItem('atlas-ti-current-user');
      location.replace('./login.html');
    }
  });
})();

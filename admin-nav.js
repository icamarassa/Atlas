/* Atlas TI — menu lateral das páginas administrativas.
 * Monta os mesmos itens em todas as páginas, mostra só o que a conta pode usar e preenche o cartão do perfil. */
(function () {
  'use strict';
  const ITEMS = [
    { href: './index.html', icon: '▤', label: 'Biblioteca' },
    { href: './admin-users.html', icon: '♙', label: 'Usuários', any: ['user.view', 'permission.manage'] },
    { href: './admin-settings.html', icon: '⌘', label: 'Active Directory', any: ['permission.manage'] },
    { href: './alert-settings.html', icon: '⚙', label: 'Alertas do sistema', any: ['document.manage', 'permission.manage'] },
    { href: './notifications.html', icon: '◷', label: 'Histórico de alertas', any: ['document.manage', 'permission.manage'] }
  ];
  const current = (location.pathname.split('/').pop() || 'index.html').toLowerCase();

  function apply(user) {
    const perms = new Set((user && user.permissions) || []);
    const known = Boolean(user && user.permissions);
    const nav = document.querySelector('.admin-nav, .main-nav');
    if (nav) {
      const classic = nav.classList.contains('main-nav'); // páginas de alertas usam outro estilo de link
      nav.innerHTML = ITEMS.filter(item => !known || !item.any || item.any.some(code => perms.has(code))).map(item => {
        const active = item.href.slice(2).toLowerCase() === current;
        return classic
          ? `<a class="nav-item${active ? ' active' : ''}" href="${item.href}"${active ? ' aria-current="page"' : ''}><span class="nav-icon">${item.icon}</span>${item.label}</a>`
          : `<a href="${item.href}"${active ? ' class="active" aria-current="page"' : ''}><span>${item.icon}</span><span>${item.label}</span></a>`;
      }).join('');
    }
    const card = document.querySelector('.sidebar-bottom .profile, .admin-sidebar .profile');
    if (card && user) {
      const name = user.name || user.login || 'Usuário';
      const roles = (user.roles || []).join(' · ') || 'Usuário';
      const initials = name.trim().split(/\s+/).slice(0, 2).map(part => part[0] || '').join('').toUpperCase();
      const avatar = card.querySelector('.avatar'), strong = card.querySelector('b'), small = card.querySelector('small');
      if (avatar) avatar.textContent = initials;
      if (strong) strong.textContent = name;
      if (small) small.textContent = roles;
    }
  }

  let cached = null;
  try { cached = JSON.parse(sessionStorage.getItem('atlas-ti-current-user') || 'null'); } catch { /* sessão sem perfil salvo */ }
  const start = () => apply(cached);
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', start); else start();
  document.addEventListener('atlas-authenticated', event => apply(event.detail));
})();

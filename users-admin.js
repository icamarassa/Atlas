/* Atlas TI — usuários, grupos e alterações.
 * Componente único usado pelo pop-up (index.html) e pela página fixa (admin-users.html).
 * Uso: AtlasUsers.mount(elemento, { mode:'popup'|'page', identity:{roles,permissions}, tab, onBack, toast }) */
(function () {
  'use strict';

  const TOKEN_KEY = 'atlas-ti-admin-token';
  const MASTER = 'Master';

  const PERMISSION_GROUPS = [
    { title: 'Documentos', items: [
      ['document.read', 'Visualizar documentos', 'Abrir e baixar documentos publicados.'],
      ['document.create', 'Criar documentos', 'Cadastrar novos documentos.'],
      ['document.edit', 'Editar e versionar', 'Alterar dados e enviar novas versões.'],
      ['document.submit', 'Enviar para aprovação', 'Submeter uma versão para revisão.'],
      ['document.approve', 'Aprovar versões', 'Aprovar ou rejeitar o que outros enviaram.'],
      ['document.change_state', 'Alterar estado', 'Marcar como obsoleto, inativo ou em revisão.'],
      ['document.manage', 'Ocultar e corrigir autoria', 'Ocultar documentos e trocar o responsável.'],
      ['document.delete', 'Excluir documentos', 'Remover documentos da biblioteca.']
    ] },
    { title: 'Catálogo', items: [
      ['catalog.manage', 'Categorias e sistemas', 'Criar e editar categorias e sistemas.']
    ] },
    { title: 'Usuários', items: [
      ['user.view', 'Visualizar usuários', 'Ver a lista, os perfis e as alterações.'],
      ['user.delete', 'Excluir usuários', 'Excluir e restaurar contas.']
    ] },
    { title: 'Administração', items: [
      ['permission.manage', 'Grupos, permissões e AD', 'Atribuir grupos aos usuários, editar grupos e configurar o Active Directory.']
    ] }
  ];
  const PERMISSION_LABEL = Object.fromEntries(PERMISSION_GROUPS.flatMap(group => group.items.map(([code, label]) => [code, label])));
  const DOCUMENT_TYPES = [['Manual', 'Manual'], ['POP', 'POP'], ['Politica', 'Política'], ['Procedimento', 'Procedimento']];
  const ACTIONS = {
    RolesUpdated: 'alterou os grupos de', UserDeleted: 'excluiu o usuário', UserRestored: 'restaurou o usuário',
    RoleCreated: 'criou o grupo', RoleUpdated: 'atualizou o grupo', DocumentScopesUpdated: 'alterou os limites de visualização do grupo',
    DocumentHidden: 'ocultou o documento', DocumentUnhidden: 'reexibiu o documento', DocumentDeleted: 'excluiu o documento',
    DocumentAttributionCorrected: 'corrigiu a autoria do documento', StateChanged: 'alterou o estado do documento',
    Updated: 'atualizou o documento', VersionCreated: 'criou uma versão do documento', ApprovalRequested: 'enviou para aprovação o documento',
    ApprovalDecision: 'decidiu a aprovação do documento', CategoryCreated: 'criou a categoria', CategoryUpdated: 'atualizou a categoria',
    SystemCreated: 'criou o sistema', SystemUpdated: 'atualizou o sistema'
  };
  const ENTITY_FILTERS = [['', 'Tudo'], ['User', 'Usuários'], ['Role', 'Grupos'], ['Document', 'Documentos'], ['Category', 'Categorias'], ['System', 'Sistemas']];

  const esc = value => String(value ?? '').replace(/[&<>"']/g, ch => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[ch]));
  const initials = name => String(name || '?').trim().split(/\s+/).slice(0, 2).map(part => part[0] || '').join('').toUpperCase() || '?';
  const fold = text => String(text || '').normalize('NFD').replace(/[\u0300-\u036f]/g, '').toLowerCase();
  const hue = text => [...String(text || '')].reduce((sum, ch) => (sum * 31 + ch.charCodeAt(0)) % 360, 7);
  const avatar = (name, size = '') => `<span class="au-avatar ${size}" style="--h:${hue(name)}" aria-hidden="true">${esc(initials(name))}</span>`;
  const fmtDate = (iso, withTime = true) => iso ? new Date(iso).toLocaleString('pt-BR', withTime ? { dateStyle: 'short', timeStyle: 'short' } : { dateStyle: 'medium' }) : '—';
  function ago(iso, never = 'Nunca acessou') {
    if (!iso) return never;
    const seconds = (Date.now() - new Date(iso).getTime()) / 1000;
    if (seconds < 90) return 'agora há pouco';
    if (seconds < 3600) return `há ${Math.floor(seconds / 60)} min`;
    if (seconds < 86400) return `há ${Math.floor(seconds / 3600)} h`;
    if (seconds < 86400 * 30) return `há ${Math.floor(seconds / 86400)} d`;
    return fmtDate(iso, false);
  }

  async function api(path, options = {}) {
    const response = await fetch('/api' + path, {
      ...options,
      headers: { 'Content-Type': 'application/json', Authorization: 'Bearer ' + sessionStorage.getItem(TOKEN_KEY), ...(options.headers || {}) }
    });
    if (!response.ok) {
      let message = `Falha na solicitação (HTTP ${response.status}).`;
      try { const body = await response.json(); message = body.error || body.detail || body.title || message; } catch { /* corpo vazio */ }
      const error = new Error(message); error.status = response.status; throw error;
    }
    return response.status === 204 ? null : response.json();
  }

  function mount(root, options = {}) {
    const identity = options.identity || {};
    const perms = new Set(identity.permissions || []);
    const can = code => perms.has(code);
    const actorIsMaster = (identity.roles || []).includes(MASTER);
    const ctx = {
      stack: [], view: null, dirty: false, roles: null, categories: null,
      filters: { q: '', status: 'active', role: '' }, users: [], auditEntity: ''
    };

    const tabs = [
      ['users', 'Usuários', can('user.view') || can('permission.manage')],
      ['groups', 'Grupos', can('user.view') || can('permission.manage')],
      ['changes', 'Alterações', can('user.view')]
    ].filter(tab => tab[2]);
    const tabOf = view => ({ profile: 'users', group: 'groups' }[view.type] || view.type);
    const titleOf = view => ({ users: 'Usuários', groups: 'Grupos', changes: 'Alterações', profile: view.name || 'Perfil', group: view.name || 'Novo grupo' }[view.type]);

    root.classList.add('au', options.mode === 'popup' ? 'au-popup' : 'au-page');
    root.innerHTML = '';
    const toast = message => {
      if (typeof options.toast === 'function') return options.toast(message);
      let node = document.querySelector('.au-toast');
      if (!node) { node = document.createElement('div'); node.className = 'au-toast'; node.setAttribute('role', 'status'); document.body.append(node); }
      node.textContent = message; node.classList.add('show');
      clearTimeout(node._timer); node._timer = setTimeout(() => node.classList.remove('show'), 3400);
    };

    /* ---------- navegação ---------- */
    function open(view, { reset = false } = {}) {
      if (ctx.dirty && !confirm('Há alterações não salvas. Descartar e continuar?')) return;
      ctx.dirty = false;
      if (reset) ctx.stack = []; else if (ctx.view) ctx.stack.push(ctx.view);
      ctx.view = view;
      render();
    }
    function back() {
      if (ctx.dirty && !confirm('Há alterações não salvas. Descartar e voltar?')) return;
      ctx.dirty = false;
      const previous = ctx.stack.pop();
      if (previous) { ctx.view = previous; render(); } else if (typeof options.onBack === 'function') options.onBack();
    }
    const backLabel = () => ctx.stack.length ? titleOf(ctx.stack[ctx.stack.length - 1]) : (options.onBack ? (options.backLabel || 'Administração') : '');

    /* ---------- dados ---------- */
    const loadRoles = async (force = false) => (ctx.roles && !force) ? ctx.roles : (ctx.roles = await api('/admin/roles'));
    const loadCategories = async () => ctx.categories || (ctx.categories = await api('/categories').catch(() => []));

    /* ---------- peças de interface ---------- */
    const pill = (text, kind = '') => `<span class="au-pill ${kind}">${esc(text)}</span>`;
    const statusPill = user => user.deletedAt ? pill('Excluído', 'del') : user.isActive ? '' : pill('Inativo', 'off');
    const roleChips = (user, limit = 3) => {
      const chips = [...(user.manualRoles || []).map(name => ({ name, ad: false })), ...(user.jitRoles || []).filter(name => !(user.manualRoles || []).includes(name)).map(name => ({ name, ad: true }))];
      if (!chips.length) return '<span class="au-muted">Sem grupo</span>';
      const shown = chips.slice(0, limit).map(chip => pill(chip.name + (chip.ad ? ' · AD' : ''), chip.name === MASTER ? 'master' : chip.ad ? 'ad' : '')).join('');
      return shown + (chips.length > limit ? pill('+' + (chips.length - limit)) : '');
    };
    const header = () => {
      const label = backLabel();
      const tabHtml = tabs.map(([key, text]) => `<button type="button" role="tab" aria-selected="${tabOf(ctx.view) === key}" class="${tabOf(ctx.view) === key ? 'active' : ''}" data-au="tab" data-tab="${key}">${text}</button>`).join('');
      return `<div class="au-top">${label ? `<button type="button" class="au-back" data-au="back" aria-label="Voltar para ${esc(label)}"><span aria-hidden="true">‹</span> ${esc(label)}</button>` : '<span></span>'}</div>
        <nav class="au-tabs" role="tablist">${tabHtml}</nav>`;
    };
    const shell = body => { root.innerHTML = header() + `<div class="au-body">${body}</div>`; };
    const failure = error => {
      root.innerHTML = header() + `<div class="au-body"><div class="au-empty"><b>Não foi possível carregar</b><p>${esc(error.message)}</p><button type="button" class="au-btn" data-au="retry">Tentar novamente</button></div></div>`;
    };

    /* ---------- lista de usuários ---------- */
    function filteredUsers() {
      const { q, status, role } = ctx.filters, needle = fold(q);
      return ctx.users.filter(user => {
        if (status === 'active' && !user.isActive) return false;
        if (status === 'inactive' && user.isActive) return false;
        if (role && ![...(user.manualRoles || []), ...(user.jitRoles || [])].includes(role)) return false;
        return !needle || fold(`${user.name} ${user.externalId} ${user.email}`).includes(needle);
      });
    }
    function userRows() {
      const list = filteredUsers();
      if (!list.length) return `<div class="au-empty"><b>Nenhum usuário encontrado</b><p>${ctx.filters.q || ctx.filters.role ? 'Ajuste a busca ou os filtros.' : ctx.filters.status === 'deleted' ? 'Não há usuários excluídos.' : 'Contas são criadas no primeiro login com o Active Directory.'}</p></div>`;
      return list.map(user => `<button type="button" class="au-row ${user.deletedAt || !user.isActive ? 'dim' : ''}" data-au="profile" data-id="${user.id}" data-name="${esc(user.name)}">
        ${avatar(user.name)}
        <span class="au-row-main"><b>${esc(user.name)} ${statusPill(user)}</b><small>${esc(user.externalId)} · ${esc(user.email)}</small></span>
        <span class="au-row-roles">${roleChips(user)}</span>
        <span class="au-row-last">${user.deletedAt ? 'Excluído ' + ago(user.deletedAt) : ago(user.lastLoginAt)}</span>
      </button>`).join('');
    }
    function refreshUserList() {
      const list = root.querySelector('[data-au-list]'), count = root.querySelector('[data-au-count]');
      if (list) list.innerHTML = userRows();
      if (count) count.textContent = `${filteredUsers().length} de ${ctx.users.length} usuário${ctx.users.length === 1 ? '' : 's'}`;
    }
    async function renderUsers() {
      const deleted = ctx.filters.status === 'deleted';
      const [users, roles] = await Promise.all([api('/admin/users' + (deleted ? '?deleted=true' : '')), loadRoles()]);
      ctx.users = users; ctx.loadedDeleted = deleted;
      const statusOptions = [['active', 'Ativos'], ['inactive', 'Inativos'], ['all', 'Todos']].concat(can('user.delete') ? [['deleted', 'Excluídos']] : []);
      shell(`<div class="au-toolbar">
          <label class="au-search"><span class="au-sr">Buscar usuário</span><input type="search" placeholder="Buscar por nome, login ou e-mail" value="${esc(ctx.filters.q)}" data-au-input="q" autocomplete="off"></label>
          <label class="au-select"><span class="au-sr">Estado</span><select data-au-input="status">${statusOptions.map(([value, text]) => `<option value="${value}" ${ctx.filters.status === value ? 'selected' : ''}>${text}</option>`).join('')}</select></label>
          <label class="au-select"><span class="au-sr">Grupo</span><select data-au-input="role"><option value="">Todos os grupos</option>${roles.map(item => `<option ${ctx.filters.role === item.role ? 'selected' : ''}>${esc(item.role)}</option>`).join('')}</select></label>
        </div>
        <p class="au-count" data-au-count aria-live="polite"></p>
        <div class="au-list" data-au-list></div>`);
      refreshUserList();
    }

    /* ---------- perfil ---------- */
    async function renderProfile() {
      const [user, roles] = await Promise.all([api('/admin/users/' + ctx.view.id), loadRoles()]);
      ctx.view.name = user.name; ctx.view.user = user;
      const manual = user.roles.filter(item => item.source === 'Manual').map(item => item.name), viaAd = user.roles.filter(item => item.source !== 'Manual').map(item => item.name);
      const isSelf = String(identity.subject || identity.login || '').toLowerCase() === String(user.externalId).toLowerCase();
      const editable = can('permission.manage') && !user.deletedAt;
      const dir = user.directory || {};
      const field = (label, value) => `<div><dt>${label}</dt><dd>${value ? esc(value) : '<span class="au-muted">—</span>'}</dd></div>`;
      const roleBox = item => {
        const isManual = manual.includes(item.role), isAd = viaAd.includes(item.role) && !isManual;
        const locked = !editable || isAd || (item.role === MASTER && !actorIsMaster);
        const keep = locked && isManual ? 'data-au-keep' : '';
        return `<label class="au-check ${locked ? 'locked' : ''}"><input type="checkbox" value="${esc(item.role)}" data-au-role ${keep} ${isManual || isAd ? 'checked' : ''} ${locked ? 'disabled' : ''}>
          <span><b>${esc(item.role)}</b>${isAd ? ' ' + pill('via Active Directory', 'ad') : ''}${item.role === MASTER ? ' ' + pill('acesso total', 'master') : ''}<small>${esc(item.description || 'Sem descrição')}</small></span></label>`;
      };
      const statusText = user.deletedAt ? pill('Excluído', 'del') : user.isActive ? pill('Ativo', 'ok') : pill('Inativo', 'off');
      const activity = user.activity.length ? user.activity.map(item => `<li><span>${esc(ACTIONS[item.action] || item.action)}</span><time>${fmtDate(item.occurredAt)}</time></li>`).join('') : '<li class="au-muted">Nenhuma atividade registrada.</li>';
      const perms = user.permissions.length ? user.permissions.map(code => pill(PERMISSION_LABEL[code] || code)).join('') : '<span class="au-muted">Nenhuma permissão.</span>';
      shell(`<section class="au-profile-head">${avatar(user.name, 'lg')}
          <div><h2>${esc(user.name)} ${statusText}</h2><p>${esc(user.externalId)} · ${esc(user.email)}</p></div></section>
        <div class="au-cols">
          <section class="au-card"><h3>Dados da conta</h3><dl class="au-dl">
            ${field('Login', user.externalId)}${field('E-mail', user.email)}${field('Cadastrado em', fmtDate(user.createdAt))}${field('Último acesso', user.lastLoginAt ? fmtDate(user.lastLoginAt) + ' (' + ago(user.lastLoginAt) + ')' : 'Nunca acessou')}
            ${field('Cargo', dir.title)}${field('Departamento', dir.department)}${field('Empresa', dir.company)}${field('Telefone', dir.telephoneNumber || dir.mobile)}
          </dl></section>
          <section class="au-card"><h3>Atividade</h3>
            <div class="au-stats"><div><b>${user.stats.documents}</b><span>documentos</span></div><div><b>${user.stats.versions}</b><span>versões</span></div><div><b>${user.stats.submitted}</b><span>envios</span></div><div><b>${user.stats.decided}</b><span>decisões</span></div></div>
            <ul class="au-activity">${activity}</ul></section>
        </div>
        <section class="au-card"><h3>Grupos</h3>
          <p class="au-hint">${editable ? 'Marque os grupos desta conta. Grupos que vêm do Active Directory são atribuídos no login e não podem ser alterados aqui.' : 'Você pode ver os grupos, mas não alterá-los.'}</p>
          <div class="au-checks">${roles.map(roleBox).join('')}</div>
          ${editable ? '<div class="au-actions"><button type="button" class="au-btn primary" data-au="save-roles">Salvar grupos</button></div>' : ''}</section>
        <section class="au-card"><h3>Permissões efetivas</h3><div class="au-chips">${perms}</div></section>
        <section class="au-card au-danger-zone"><h3>Conta</h3>
          ${user.deletedAt ? `<p class="au-hint">Excluído em ${fmtDate(user.deletedAt)}. A pessoa não consegue entrar enquanto a conta estiver excluída.</p>${can('user.delete') ? '<div class="au-actions"><button type="button" class="au-btn primary" data-au="restore">Restaurar usuário</button></div>' : ''}` : `
            ${isSelf ? '<p class="au-hint">Esta é a sua própria conta: ela não pode ser desativada nem excluída por você.</p>' : ''}
            <div class="au-actions">
              ${can('permission.manage') && !isSelf ? `<button type="button" class="au-btn" data-au="toggle-active">${user.isActive ? 'Desativar conta' : 'Reativar conta'}</button>` : ''}
              ${can('user.delete') && !isSelf ? '<button type="button" class="au-btn danger" data-au="ask-delete">Excluir usuário…</button>' : ''}
            </div>
            <div class="au-confirm" data-au-confirm hidden><p><b>Excluir ${esc(user.name)}?</b> A pessoa perde o acesso e todos os grupos. Os documentos e o histórico continuam com o nome dela, e a conta pode ser restaurada depois. Quem existir no Active Directory continua bloqueado no Atlas TI.</p>
              <div class="au-actions"><button type="button" class="au-btn" data-au="cancel-delete">Cancelar</button><button type="button" class="au-btn danger solid" data-au="delete">Excluir usuário</button></div></div>`}
        </section>`);
    }
    async function saveUser(overrides = {}) {
      const user = ctx.view.user;
      const manual = [...root.querySelectorAll('[data-au-role]:checked:not(:disabled), [data-au-role][data-au-keep]')].map(input => input.value);
      const roles = overrides.roles || [...new Set(manual)];
      await api('/admin/users', { method: 'PUT', body: JSON.stringify({ externalId: user.externalId, displayName: user.name, email: user.email, roles, isActive: overrides.isActive ?? user.isActive }) });
    }

    /* ---------- grupos ---------- */
    async function renderGroups() {
      const [roles, users] = await Promise.all([loadRoles(true), api('/admin/users')]);
      ctx.users = users;
      const cards = roles.map(group => {
        const members = users.filter(user => [...(user.manualRoles || []), ...(user.jitRoles || [])].includes(group.role)).length;
        return `<button type="button" class="au-card au-group" data-au="group" data-name="${esc(group.role)}">
          <span class="au-group-icon ${group.role === MASTER ? 'master' : ''}" aria-hidden="true">${group.role === MASTER ? '★' : '◎'}</span>
          <b>${esc(group.role)}</b><p>${esc(group.description || 'Sem descrição')}</p>
          <small>${members} membro${members === 1 ? '' : 's'} · ${group.permissions.length} permiss${group.permissions.length === 1 ? 'ão' : 'ões'}</small></button>`;
      }).join('');
      shell(`<div class="au-toolbar"><p class="au-count grow">${roles.length} grupos de permissão</p>${can('permission.manage') ? '<button type="button" class="au-btn primary" data-au="new-group">＋ Novo grupo</button>' : ''}</div><div class="au-grid">${cards}</div>`);
    }
    async function renderGroup() {
      const name = ctx.view.name || null, isNew = !name;
      const [roles, categories, users] = await Promise.all([loadRoles(), loadCategories(), name ? api('/admin/users').catch(() => []) : []]);
      const group = isNew ? { role: '', description: '', permissions: [] } : roles.find(item => item.role === name);
      if (!group) throw new Error('Grupo não encontrado.');
      let rules = [];
      if (!isNew && can('permission.manage')) rules = (await api(`/admin/roles/${encodeURIComponent(name)}/document-scopes`).catch(() => ({ rules: [] }))).rules || [];
      const isMaster = name === MASTER, editable = can('permission.manage');
      const members = users.filter(user => [...(user.manualRoles || []), ...(user.jitRoles || [])].includes(name));
      const permissionHtml = PERMISSION_GROUPS.map(section => `<fieldset class="au-perm-group"><legend>${section.title}</legend>${section.items.map(([code, label, hint]) => `
        <label class="au-check ${isMaster || !editable ? 'locked' : ''}"><input type="checkbox" name="permissions" value="${code}" ${group.permissions.includes(code) || isMaster ? 'checked' : ''} ${isMaster || !editable ? 'disabled' : ''}><span><b>${label}</b><small>${hint}</small></span></label>`).join('')}</fieldset>`).join('');
      shell(`<form data-au-form="group" novalidate>
        <div class="au-card"><h3>${isNew ? 'Novo grupo' : esc(group.role)}</h3>
          ${isMaster ? '<p class="au-hint">O Master é o administrador do sistema: tem todas as permissões e não pode ser renomeado nem perder permissões.</p>' : ''}
          <div class="au-fields"><label class="au-field"><span>Nome do grupo</span><input name="name" maxlength="60" required value="${esc(group.role)}" ${(isMaster || name === 'Administrador' || !editable) ? 'readonly' : ''}></label>
          <label class="au-field"><span>Descrição</span><input name="description" maxlength="240" value="${esc(group.description || '')}" ${(isMaster || !editable) ? 'readonly' : ''}></label></div></div>
        <div class="au-card"><h3>Permissões</h3><div class="au-perms">${permissionHtml}</div></div>
        ${editable && !isMaster ? `<div class="au-card"><h3>Limitar visualização de documentos</h3>
          <p class="au-hint">Cada regra combina categoria <b>e</b> tipo. Regras diferentes se somam (OU). Sem regras, o grupo vê todos os documentos publicados. Quem tem acesso de Master ou Administrador ignora os limites.</p>
          <div data-au-rules></div><button type="button" class="au-btn sm" data-au="add-rule">＋ Adicionar regra</button></div>` : ''}
        ${members.length ? `<div class="au-card"><h3>Membros (${members.length})</h3><div class="au-chips">${members.map(user => `<button type="button" class="au-pill link" data-au="profile" data-id="${user.id}" data-name="${esc(user.name)}">${esc(user.name)}</button>`).join('')}</div></div>` : ''}
        ${editable ? `<div class="au-actions sticky"><button type="button" class="au-btn" data-au="back">Cancelar</button>${isMaster ? '' : '<button type="submit" class="au-btn primary">Salvar grupo</button>'}</div>` : ''}
      </form>`);
      ctx.categoryRows = categories;
      const list = root.querySelector('[data-au-rules]');
      if (list) rules.forEach(rule => addRule(list, rule));
      root.querySelector('[data-au-form]').addEventListener('input', () => { ctx.dirty = true; });
    }
    function addRule(list, rule = {}) {
      const row = document.createElement('div'); row.className = 'au-rule';
      row.innerHTML = `<label class="au-field"><span>Categoria</span><select data-rule-category><option value="">Qualquer categoria</option>${(ctx.categoryRows || []).map(item => `<option value="${Number(item.id)}">${esc(item.name)}</option>`).join('')}</select></label>
        <label class="au-field"><span>Tipo</span><select data-rule-type><option value="">Qualquer tipo</option>${DOCUMENT_TYPES.map(([value, text]) => `<option value="${value}">${text}</option>`).join('')}</select></label>
        <button type="button" class="au-btn ghost sm" data-au="remove-rule" aria-label="Remover regra">Remover</button>`;
      row.querySelector('[data-rule-category]').value = rule.categoryId || '';
      row.querySelector('[data-rule-type]').value = rule.documentType || '';
      list.append(row);
    }
    async function saveGroup(form) {
      const isNew = !ctx.view.name, data = new FormData(form), name = String(data.get('name') || '').trim();
      if (!name) throw new Error('Informe o nome do grupo.');
      const permissions = [...form.querySelectorAll('[name="permissions"]:checked')].map(input => input.value);
      await api(isNew ? '/admin/roles' : `/admin/roles/${encodeURIComponent(ctx.view.name)}`, { method: isNew ? 'POST' : 'PUT', body: JSON.stringify({ name, description: data.get('description'), permissions }) });
      const rules = [...form.querySelectorAll('.au-rule')].map(row => ({ categoryId: row.querySelector('[data-rule-category]').value ? Number(row.querySelector('[data-rule-category]').value) : null, documentType: row.querySelector('[data-rule-type]').value || null })).filter(rule => rule.categoryId !== null || rule.documentType !== null);
      if (form.querySelector('[data-au-rules]')) await api(`/admin/roles/${encodeURIComponent(name)}/document-scopes`, { method: 'PUT', body: JSON.stringify({ rules }) });
      return isNew;
    }

    /* ---------- alterações ---------- */
    async function renderChanges() {
      const items = await api('/admin/audit?take=80' + (ctx.auditEntity ? '&entity=' + ctx.auditEntity : ''));
      const rows = items.length ? items.map(item => `<li><span class="au-dot" aria-hidden="true"></span><div><p><b>${esc(item.actor || 'Sistema')}</b> ${esc(ACTIONS[item.action] || item.action)} ${item.target ? `<b>${esc(item.target)}</b>` : `<span class="au-muted">#${item.entityId}</span>`}</p><time>${fmtDate(item.occurredAt)} · ${ago(item.occurredAt)}</time></div></li>`).join('') : '<li class="au-empty"><b>Nenhuma alteração registrada</b></li>';
      shell(`<div class="au-toolbar"><label class="au-select"><span class="au-sr">Filtrar por tipo</span><select data-au-input="auditEntity">${ENTITY_FILTERS.map(([value, text]) => `<option value="${value}" ${ctx.auditEntity === value ? 'selected' : ''}>${text}</option>`).join('')}</select></label><p class="au-count grow">Últimas ${items.length} alterações</p></div><ul class="au-timeline">${rows}</ul>`);
    }

    /* ---------- renderização ---------- */
    let token = 0;
    async function render() {
      const mine = ++token;
      root.innerHTML = header() + '<div class="au-body"><div class="au-loading" role="status">Carregando…</div></div>';
      try {
        const view = ctx.view;
        if (view.type === 'users') await renderUsers();
        else if (view.type === 'profile') await renderProfile();
        else if (view.type === 'groups') await renderGroups();
        else if (view.type === 'group') await renderGroup();
        else await renderChanges();
        if (mine !== token) return;
        root.scrollTop = 0;
        options.onRender?.(ctx.view);
      } catch (error) { if (mine === token) failure(error); }
    }

    /* ---------- eventos ---------- */
    root.addEventListener('click', async event => {
      const target = event.target.closest('[data-au]');
      if (!target || !root.contains(target)) return;
      const action = target.dataset.au;
      try {
        if (action === 'tab') open({ type: target.dataset.tab }, { reset: true });
        else if (action === 'back') back();
        else if (action === 'retry') render();
        else if (action === 'profile') open({ type: 'profile', id: Number(target.dataset.id), name: target.dataset.name });
        else if (action === 'group') open({ type: 'group', name: target.dataset.name });
        else if (action === 'new-group') open({ type: 'group', name: null });
        else if (action === 'add-rule') addRule(root.querySelector('[data-au-rules]'));
        else if (action === 'remove-rule') { target.closest('.au-rule').remove(); ctx.dirty = true; }
        else if (action === 'save-roles') { target.disabled = true; await saveUser(); ctx.dirty = false; toast('Grupos atualizados'); await render(); }
        else if (action === 'toggle-active') {
          const user = ctx.view.user;
          if (user.isActive && !confirm(`Desativar a conta de ${user.name}? A pessoa não conseguirá entrar até ser reativada.`)) return;
          await saveUser({ roles: user.roles.filter(item => item.source === 'Manual').map(item => item.name), isActive: !user.isActive });
          toast(user.isActive ? 'Conta desativada' : 'Conta reativada'); await render();
        } else if (action === 'ask-delete') { root.querySelector('[data-au-confirm]').hidden = false; target.hidden = true; root.querySelector('[data-au-confirm]').scrollIntoView?.({ block: 'nearest' }); }
        else if (action === 'cancel-delete') { root.querySelector('[data-au-confirm]').hidden = true; root.querySelector('[data-au="ask-delete"]').hidden = false; }
        else if (action === 'delete') {
          target.disabled = true; await api('/admin/users/' + ctx.view.id, { method: 'DELETE' });
          toast('Usuário excluído'); ctx.dirty = false; ctx.view = ctx.stack.pop() || { type: 'users' }; render();
        } else if (action === 'restore') {
          await api(`/admin/users/${ctx.view.id}/restore`, { method: 'POST' }); toast('Usuário restaurado'); await render();
        }
      } catch (error) { toast(error.message); root.querySelectorAll('button[disabled]').forEach(button => { if (!button.closest('.au-check')) button.disabled = false; }); }
    });
    root.addEventListener('input', event => {
      const field = event.target.closest('[data-au-input]');
      if (field?.dataset.auInput === 'q') { ctx.filters.q = field.value; refreshUserList(); }
      if (event.target.matches('[data-au-role]')) ctx.dirty = true;
    });
    root.addEventListener('change', event => {
      const field = event.target.closest('[data-au-input]');
      if (!field) return;
      const key = field.dataset.auInput;
      if (key === 'status') { ctx.filters.status = field.value; if ((field.value === 'deleted') !== Boolean(ctx.loadedDeleted)) render(); else refreshUserList(); }
      else if (key === 'role') { ctx.filters.role = field.value; refreshUserList(); }
      else if (key === 'auditEntity') { ctx.auditEntity = field.value; render(); }
    });
    root.addEventListener('submit', async event => {
      const form = event.target.closest('[data-au-form="group"]');
      if (!form) return;
      event.preventDefault();
      const button = form.querySelector('[type="submit"]'); if (button) button.disabled = true;
      try { const created = await saveGroup(form); ctx.dirty = false; toast(created ? 'Grupo criado' : 'Grupo atualizado'); ctx.roles = null; ctx.stack.pop(); ctx.view = { type: 'groups' }; render(); }
      catch (error) { toast(error.message); if (button) button.disabled = false; }
    });

    const first = options.tab && tabs.some(tab => tab[0] === options.tab) ? options.tab : (tabs[0] || ['users'])[0];
    if (!tabs.length) { root.innerHTML = '<div class="au-body"><div class="au-empty"><b>Sem permissão</b><p>Sua conta não tem acesso à administração de usuários.</p></div></div>'; return { open() {} }; }
    ctx.view = { type: first };
    render();
    return { open: view => open(view, { reset: true }), refresh: render };
  }

  window.AtlasUsers = { mount };
})();

// Fetch It OAuth consent page for Supabase Auth's OAuth 2.1 server (Grok connector).
// Supabase Auth sends the browser here as  <Site URL>/oauth/consent.html?authorization_id=…
// The user signs in (email code, or password), sees who is asking, and approves or denies.
// config.js (written by scripts/build-web.sh) sets window.FETCHIT_CONFIG = { url, anonKey }.
(function () {
  'use strict';
  // never render inside a frame (clickjacking); static hosts can't send frame-ancestors headers
  if (window.top !== window.self) {
    document.body.textContent = 'Open this page directly.';
    return;
  }
  var $ = function (id) { return document.getElementById(id); };
  var cfg = window.FETCHIT_CONFIG || {};
  var TRUSTED_HOSTS = ['x.ai', 'grok.com'];
  var params = new URLSearchParams(window.location.search);
  var authorizationId = params.get('authorization_id');
  var email = '';

  function show(id) {
    ['loading', 'signin', 'consent'].forEach(function (s) { $(s).hidden = s !== id; });
    $('app').hidden = false;
  }
  function error(msg) {
    $('error').textContent = msg || '';
    $('error').hidden = !msg;
  }
  function busy(form, on) {
    Array.prototype.forEach.call(form.querySelectorAll('button, input'), function (el) { el.disabled = on; });
  }
  function hostOf(uri) {
    try { return new URL(uri).hostname.toLowerCase(); } catch (e) { return ''; }
  }
  function trusted(host) {
    return TRUSTED_HOSTS.some(function (d) { return host === d || host.slice(-(d.length + 1)) === '.' + d; });
  }
  function friendly(e) {
    var m = (e && (e.message || e.msg)) || String(e);
    if (/rate limit|security purposes/i.test(m)) return 'Too many attempts. Wait a minute and try again.';
    if (/expired|invalid.*(otp|token)|token has expired/i.test(m)) return 'That code is wrong or expired. Send a new code.';
    if (/signups not allowed|user not found/i.test(m)) return 'No Fetch It account uses that email. Sign up in the Fetch It app first.';
    if (/invalid login credentials/i.test(m)) return 'Wrong email or password.';
    return m;
  }

  if (!authorizationId) {
    show(null);
    error('This link is missing its authorization request. Start connecting Fetch It again from Grok.');
    return;
  }
  if (!cfg.url || !cfg.anonKey || !window.supabase) {
    show(null);
    error('Fetch It is not configured on this site.');
    return;
  }

  var sb = window.supabase.createClient(cfg.url, cfg.anonKey, {
    auth: { storageKey: 'fetchit-oauth-consent', persistSession: true, autoRefreshToken: true, detectSessionInUrl: false },
  });

  function go(url) {
    // only ever leave for the URL Supabase Auth returned (the client's registered redirect URI)
    if (!/^https?:\/\//i.test(url)) return error('Unexpected redirect from Fetch It.');
    window.location.replace(url);
  }

  async function loadConsent() {
    show('loading');
    error('');
    var res = await sb.auth.oauth.getAuthorizationDetails(authorizationId);
    if (res.error) {
      show(null);
      return error(/not found|expired/i.test(res.error.message) ? 'This request expired. Start connecting Fetch It again from Grok.' : friendly(res.error));
    }
    var d = res.data || {};
    // already approved before: Supabase returns where to go next
    if (!d.authorization_id && d.redirect_url) return go(d.redirect_url);
    var name = (d.client && (d.client.client_name || d.client.name)) || 'An app';
    var host = hostOf(d.redirect_uri);
    $('title').textContent = 'Connect ' + name;
    $('client-name').textContent = name;
    $('who').textContent = (d.user && d.user.email) || email || 'you';
    $('redirect-note').textContent = host ? 'After you choose, you go back to ' + host + '.' : '';
    if (host && !trusted(host)) {
      $('untrusted').hidden = false;
      $('untrusted').textContent = 'This app is not Grok (' + host + '). Only allow it if you set it up yourself.';
    }
    show('consent');
  }

  async function decide(approve) {
    var btns = [$('approve'), $('deny')];
    btns.forEach(function (b) { b.disabled = true; });
    error('');
    var res = approve
      ? await sb.auth.oauth.approveAuthorization(authorizationId, { skipBrowserRedirect: true })
      : await sb.auth.oauth.denyAuthorization(authorizationId, { skipBrowserRedirect: true });
    if (res.error || !res.data || !res.data.redirect_url) {
      btns.forEach(function (b) { b.disabled = false; });
      return error(friendly(res.error || 'No redirect returned.'));
    }
    go(res.data.redirect_url);
  }

  $('email-form').addEventListener('submit', async function (ev) {
    ev.preventDefault();
    email = $('email').value.trim().toLowerCase();
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(email)) return error('Enter your email address.');
    busy(this, true);
    error('');
    // shouldCreateUser: false -> only existing Fetch It accounts can connect
    var res = await sb.auth.signInWithOtp({ email: email, options: { shouldCreateUser: false } });
    busy(this, false);
    if (res.error) return error(friendly(res.error));
    $('email-form').hidden = true;
    $('code-form').hidden = false;
    $('code-sent').textContent = 'We sent a code to ' + email + '. It can take a minute to arrive.';
    $('code').focus();
  });

  $('code-form').addEventListener('submit', async function (ev) {
    ev.preventDefault();
    var token = $('code').value.replace(/\D/g, '');
    if (token.length < 6) return error('Enter the code from the email.');
    busy(this, true);
    error('');
    var res = await sb.auth.verifyOtp({ email: email, token: token, type: 'email' });
    busy(this, false);
    if (res.error) return error(friendly(res.error));
    loadConsent();
  });

  $('resend').addEventListener('click', function () {
    $('code-form').hidden = true;
    $('email-form').hidden = false;
    $('code').value = '';
  });

  $('use-password').addEventListener('click', function () {
    $('password-form').hidden = !$('password-form').hidden;
    $('pw-email').value = $('email').value;
  });

  $('password-form').addEventListener('submit', async function (ev) {
    ev.preventDefault();
    email = $('pw-email').value.trim().toLowerCase();
    busy(this, true);
    error('');
    var res = await sb.auth.signInWithPassword({ email: email, password: $('password').value });
    busy(this, false);
    if (res.error) return error(friendly(res.error));
    loadConsent();
  });

  $('approve').addEventListener('click', function () { decide(true); });
  $('deny').addEventListener('click', function () { decide(false); });
  $('switch').addEventListener('click', async function () {
    await sb.auth.signOut({ scope: 'local' });
    show('signin');
  });

  sb.auth.getSession().then(function (r) {
    if (r.data && r.data.session) return loadConsent();
    show('signin');
  });
})();

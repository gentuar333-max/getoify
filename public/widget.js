(function () {
  var GETOIFY_API = 'https://www.getoify.com';

  var LANG_LABELS = {
    fr: 'FR', de: 'DE', it: 'IT', es: 'ES',
    pt: 'PT', nl: 'NL', pl: 'PL', en: 'EN'
  };

  var LANG_NAMES = {
    fr: 'French', de: 'German', it: 'Italian', es: 'Spanish',
    pt: 'Portuguese', nl: 'Dutch', pl: 'Polish', en: 'English'
  };

  function getShop() {
    return window.Shopify && window.Shopify.shop ? window.Shopify.shop : null;
  }

  function getCurrentLocale() {
    var path = window.location.pathname;
    var match = path.match(/^\/([a-z]{2})(\/|$)/);
    return match ? match[1] : 'en';
  }

  function buildSwitcher(locales) {
    if (!locales || locales.length === 0) return;

    var all = locales.indexOf('en') === -1 ? ['en'].concat(locales) : locales;
    var current = getCurrentLocale();

    var wrap = document.createElement('div');
    wrap.id = 'getoify-lang-switcher';
    wrap.style.cssText = [
      'position:fixed',
      'bottom:20px',
      'right:20px',
      'z-index:9999',
      'display:flex',
      'gap:3px',
      'background:#ffffff',
      'border:1px solid #e0e0e0',
      'border-radius:8px',
      'padding:4px',
      'box-shadow:0 2px 12px rgba(0,0,0,0.10)',
      'font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif'
    ].join(';');

    all.forEach(function (locale) {
      var btn = document.createElement('button');
      var isActive = locale === current;
      btn.textContent = LANG_LABELS[locale] || locale.toUpperCase();
      btn.title = LANG_NAMES[locale] || locale;
      btn.style.cssText = [
        'padding:5px 10px',
        'border:none',
        'border-radius:5px',
        'font-size:12px',
        'font-weight:' + (isActive ? '600' : '400'),
        'cursor:' + (isActive ? 'default' : 'pointer'),
        'background:' + (isActive ? '#f0ede6' : 'transparent'),
        'color:' + (isActive ? '#1c1b18' : '#5c5850'),
        'font-family:inherit',
        'transition:background 0.15s,color 0.15s',
        'outline:none'
      ].join(';');

      if (!isActive) {
        btn.onmouseover = function () {
          btn.style.background = '#f5f5f5';
          btn.style.color = '#1c1b18';
        };
        btn.onmouseout = function () {
          btn.style.background = 'transparent';
          btn.style.color = '#5c5850';
        };
        btn.onclick = function () {
          var path = window.location.pathname;
          var cleaned = path.replace(/^\/(fr|de|it|es|pt|nl|pl|en)(\/|$)/, '/');
          var newPath = locale === 'en' ? cleaned : '/' + locale + cleaned;
          window.location.href = newPath + window.location.search;
        };
      }

      wrap.appendChild(btn);
    });

    document.body.appendChild(wrap);
  }

  function init() {
    var shop = getShop();
    if (!shop) return;

    if (document.getElementById('getoify-lang-switcher')) return;

    var xhr = new XMLHttpRequest();
    xhr.open('GET', GETOIFY_API + '/widget-config?shop=' + encodeURIComponent(shop));
    xhr.onload = function () {
      if (xhr.status === 200) {
        try {
          var data = JSON.parse(xhr.responseText);
          if (data.locales && data.locales.length > 0) {
            buildSwitcher(data.locales);
          }
        } catch (e) {}
      }
    };
    xhr.onerror = function () {};
    xhr.send();
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();
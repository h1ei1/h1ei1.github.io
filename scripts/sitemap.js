'use strict';

// Zero-dependency sitemap generator: outputs /sitemap.xml listing the
// homepage, all posts and all pages so search engines can discover them.
// Installed as a local script to avoid touching the frozen pnpm lockfile.

hexo.extend.generator.register('sitemap', function (locals) {
  var base = hexo.config.url.replace(/\/+$/, '');
  var entries = [{ path: '', date: new Date() }];

  locals.posts.toArray().forEach(function (p) {
    entries.push({ path: p.path, date: p.updated || p.date });
  });
  locals.pages.toArray().forEach(function (p) {
    entries.push({ path: p.path, date: p.updated || p.date });
  });

  var urls = entries.map(function (e) {
    var loc = base + '/' + encodeURI(e.path || '').replace(/^\/+/, '');
    var lastmod = (e.date ? new Date(e.date) : new Date()).toISOString().slice(0, 10);
    return '  <url>\n    <loc>' +
      loc.replace(/&/g, '&amp;') +
      '</loc>\n    <lastmod>' + lastmod + '</lastmod>\n  </url>';
  });

  var xml = '<?xml version="1.0" encoding="UTF-8"?>\n' +
    '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n' +
    urls.join('\n') +
    '\n</urlset>\n';

  return { path: 'sitemap.xml', data: xml };
});

const fs = require('fs');
const path = require('path');
const zlib = require('zlib');
const { execSync } = require('child_process');
const os = require('os');

const GITHUB_USER = process.env.GITHUB_REPOSITORY?.split('/')[0] || 'ground-zerro';
const GITHUB_REPO = process.env.GITHUB_REPOSITORY?.split('/')[1] || 'release';
const repoBaseUrl = `https://${GITHUB_USER.toLowerCase()}.github.io/${GITHUB_REPO}`;
const rootDirs = ['keenetic'];
const isGitHubCI = process.env.GITHUB_ACTIONS === 'true';
const repoRoot = isGitHubCI ? path.resolve(process.cwd()) : __dirname;

const embeddedCSS = `
body { font-family: sans-serif; background: #f8f8f8; color: #222; padding: 20px; }
table { width: 100%; border-collapse: collapse; }
th, td { text-align: left; padding: 8px; border-bottom: 1px solid #ddd; }
th { background: #f0f0f0; cursor: pointer; }
.search { margin: 10px 0; padding: 5px; width: 200px; }
a { color: #0366d6; text-decoration: none; }
a:hover { text-decoration: underline; }
`;

function compareVersions(v1, v2) {
  const normalize = v => v.replace(/[^0-9]/g, '').padStart(8, '0');
  return parseInt(normalize(v1)) - parseInt(normalize(v2));
}

function formatSize(bytes) {
  const units = ['B', 'KB', 'MB', 'GB'];
  let i = 0;
  while (bytes >= 1024 && i < units.length - 1) {
    bytes /= 1024;
    i++;
  }
  return `${bytes.toFixed(1)} ${units[i]}`;
}

function parseControlFields(content) {
  const result = {};
  content.split('\n').forEach(line => {
    const [key, ...rest] = line.split(':');
    if (key && rest.length) {
      result[key.trim()] = rest.join(':').trim();
    }
  });
  return result;
}

function extractControlFromIpk(ipkPath) {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'ipk-'));
  try {
    const controlTar = execSync(`tar -xOf "${ipkPath}" control.tar.gz`);
    fs.writeFileSync(path.join(tmpDir, 'control.tar.gz'), controlTar);
    execSync(`tar -xzf control.tar.gz`, { cwd: tmpDir });
    const controlContent = fs.readFileSync(path.join(tmpDir, 'control')).toString();
    return parseControlFields(controlContent);
  } catch (e) {
    console.error(`⚠️ Failed to parse .ipk: ${ipkPath}`);
    return null;
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
}

function generatePackagesFiles(dir, relPath) {
  const entries = fs.readdirSync(dir);
  const ipkFiles = entries.filter(f => f.endsWith('.ipk'));
  if (ipkFiles.length === 0) return;

  const packageEntries = [];

  for (const file of ipkFiles) {
    const ipkPath = path.join(dir, file);
    const control = extractControlFromIpk(ipkPath);
    if (!control || !control.Package || !control.Version || !control.Architecture) continue;

    packageEntries.push({
      name: control.Package,
      version: control.Version,
      arch: control.Architecture,
      filename: file,
      size: fs.statSync(ipkPath).size,
      control
    });
  }

  // Выбор только самых новых версий
  const latestMap = {};
  for (const entry of packageEntries) {
    const key = `${entry.name}_${entry.arch}`;
    if (!latestMap[key] || compareVersions(entry.version, latestMap[key].version) > 0) {
      latestMap[key] = entry;
    }
  }

  const finalPackages = Object.values(latestMap);
  const packages = [];
  for (const entry of finalPackages) {
    const control = entry.control;
    const block = [
      `Package: ${control.Package}`,
      `Version: ${control.Version}`,
      `Architecture: ${control.Architecture}`,
      `Maintainer: ${control.Maintainer || 'unknown'}`,
      `Depends: ${control.Depends || ''}`,
      `Section: ${control.Section || 'base'}`,
      `Priority: ${control.Priority || 'optional'}`,
      `Filename: ${entry.filename}`,
      `Size: ${entry.size}`,
      `Description: ${control.Description || ''}`,
      ''
    ].join('\n');
    packages.push(block);
  }

  const allText = packages.join('\n');
  fs.writeFileSync(path.join(dir, 'Packages'), allText);
  fs.writeFileSync(path.join(dir, 'Packages.gz'), zlib.gzipSync(allText));

  let html = `<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>Packages in /${relPath}</title>
<style>${embeddedCSS}</style>
</head>
<body>
<h1>Packages in /${relPath}</h1>
<table>
<thead><tr><th>Name</th><th>Version</th><th>Section</th><th>Description</th></tr></thead>
<tbody>`;
  for (const block of packages) {
    const lines = block.split('\n');
    const data = {};
    lines.forEach(line => {
      const [key, ...rest] = line.split(':');
      if (key && rest.length) {
        data[key.trim()] = rest.join(':').trim();
      }
    });
    html += `<tr><td><a href="${data.Filename}">${data.Package}</a></td><td>${data.Version}</td><td>${data.Section || ''}</td><td>${data.Description || ''}</td></tr>`;
  }
  html += '</tbody></table></body></html>';
  fs.writeFileSync(path.join(dir, 'Packages.html'), html);
}

function generateIndexForDir(currentPath, rootDirAbs, rootDirRel) {
  generatePackagesFiles(currentPath, path.posix.join(rootDirRel, path.relative(rootDirAbs, currentPath).replace(/\\/g, '/')));

  const entries = fs.readdirSync(currentPath, { withFileTypes: true });
  const relativePathFromRoot = path.relative(rootDirAbs, currentPath).replace(/\\/g, '/');
  const fullPathFromRepo = path.posix.join(rootDirRel, relativePathFromRoot);
  const folderUrl = `/${fullPathFromRepo}/`.replace(/\/+/g, '/');
  const baseHref = `${repoBaseUrl}/${fullPathFromRepo}/`.replace(/\\+/g, '/').replace(/([^:]\/)\/+/g, '$1');

  const files = entries.filter(e => e.isFile() && e.name !== 'index.html')
    .map(e => ({ name: e.name, size: formatSize(fs.statSync(path.join(currentPath, e.name)).size) }))
    .sort((a, b) => a.name.localeCompare(b.name));

  const dirs = entries.filter(e => e.isDirectory())
    .map(e => ({ name: e.name + '/', size: '-' }))
    .sort((a, b) => a.name.localeCompare(b.name));

  const parentPath = fullPathFromRepo.split('/').slice(0, -1).join('/');
  const parentUrl = parentPath ? `${repoBaseUrl}/${parentPath}/` : `${repoBaseUrl}/`;

  const rows = [
    { name: '..', size: '', href: parentUrl },
    ...dirs.map(d => ({ ...d, href: `${baseHref}${encodeURI(d.name)}` })),
    ...files.map(f => ({ ...f, href: `${baseHref}${encodeURI(f.name)}` }))
  ];

  let html = `<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8">
<title>Index of ${folderUrl}</title>
<style>
body { font-family: monospace; padding: 2em; background: #fafafa; color: #333; }
table { width: 100%; max-width: 800px; border-collapse: collapse; }
td { padding: 0.3em 0.6em; border-bottom: 1px solid #ddd; }
td.size { text-align: right; color: #666; white-space: nowrap; }
a { color: #0366d6; text-decoration: none; }
a:hover { text-decoration: underline; }
h1 { margin-bottom: 1em; }
</style></head><body>
<h1>Index of ${folderUrl}</h1>
<table>`;
  for (const row of rows) {
    html += `<tr><td><a href="${row.href}">${row.name}</a></td><td class="size">${row.size}</td></tr>\n`;
  }
  html += '</table></body></html>';
  fs.writeFileSync(path.join(currentPath, 'index.html'), html, 'utf-8');
}

function walkAndGenerate(currentDir, rootDirAbs, rootDirRel) {
  generateIndexForDir(currentDir, rootDirAbs, rootDirRel);
  const entries = fs.readdirSync(currentDir, { withFileTypes: true });
  for (const entry of entries) {
    if (entry.isDirectory()) {
      walkAndGenerate(path.join(currentDir, entry.name), rootDirAbs, rootDirRel);
    }
  }
}

for (const rootDirRel of rootDirs) {
  const rootDirAbs = path.join(repoRoot, rootDirRel);
  if (fs.existsSync(rootDirAbs)) {
    walkAndGenerate(rootDirAbs, rootDirAbs, rootDirRel);
  } else {
    console.warn(`⚠ Directory not found: ${rootDirRel}`);
  }
}

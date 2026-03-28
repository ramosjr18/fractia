/**
 * deps.dart.js — Dependencias (pubspec.yaml audit)
 */
import { auditPubspec } from '../utils/pubspecParser.js';

export const meta = { id: 'deps', name: 'Dependencies (pubspec)', severity: 'high', pilar: 'Mobile' };

export async function scan({ dartFiles, pubspec, projectRoot }) {
  const findings = [];
  if (!pubspec) {
    return { module: meta.id, name: meta.name, severity: 'medium', findings: [{
      severity: 'medium', title: 'pubspec.yaml no encontrado',
      description: 'No se pudo parsear pubspec.yaml. Verifica la ruta del proyecto.',
      file: null, line: null, code: null, fix: 'Asegúrate de apuntar a la raíz del proyecto Flutter.', cve: null,
    }], passed: false, summary: 'pubspec.yaml no analizable' };
  }

  const { findings: vulnFindings, missing, unpinned } = auditPubspec(pubspec);

  // Vulnerable packages
  for (const v of vulnFindings) {
    findings.push({
      severity:    v.severity,
      title:       `Paquete vulnerable: ${v.package}`,
      description: v.reason,
      file:        'pubspec.yaml', line: null, code: null,
      fix:         v.type === 'dev_in_prod'
        ? `Mueve ${v.package} a dev_dependencies`
        : `Actualiza o reemplaza ${v.package}`,
      cve: null,
    });
  }

  // Missing security packages
  for (const m of missing) {
    findings.push({
      severity:    m.severity,
      title:       `Falta paquete de seguridad: ${m.package}`,
      description: m.reason,
      file:        'pubspec.yaml', line: null, code: null,
      fix:         `Añade ${m.package} a dependencies en pubspec.yaml`,
      cve:         'CWE-1357',
    });
  }

  // Unpinned versions
  if (unpinned.length > 3) {
    findings.push({
      severity: 'low',
      title:    `${unpinned.length} dependencias con versión no fijada`,
      description: `Paquetes con ^ o "any" pueden actualizarse automáticamente a versiones con breaking changes o vulnerabilidades: ${unpinned.slice(0,5).map(d=>d.name).join(', ')}...`,
      file: 'pubspec.yaml', line: null, code: null,
      fix: 'Considera pinear versiones exactas en producción y usar flutter pub upgrade solo con revisión manual.',
      cve: 'CWE-1357: Reliance on Insufficiently Trustworthy Component',
    });
  }

  return buildResult(findings);
}

function buildResult(findings) {
  const rank = { critical: 4, high: 3, medium: 2, low: 1, ok: 0 };
  const maxSev = findings.reduce((b, f) => rank[f.severity] > rank[b] ? f.severity : b, 'ok');
  return { module: meta.id, name: meta.name, severity: findings.length ? maxSev : 'ok', findings, passed: findings.length === 0,
    summary: findings.length ? `${findings.length} problema(s) en dependencias` : 'Dependencias sin vulnerabilidades conocidas' };
}

import path from 'path';
import { readFile, grepFiles, truncate } from '../utils/fileScanner.js';
import { detectProjectType } from '../utils/projectType.js';

/**
 * Agentic Security Auditor (LLM Protection)
 * Focuses on: Tool Integrity, Prompt Injection, Output Sanitization, SSRF, and RAG Leakage.
 */

async function auditNode(structure) {
  const findings = [];
  const recommendations = [];
  const _codeSnippets = {};
  const src = structure.srcDir;
  const jsExtensions = ['.js', '.ts', '.jsx', '.tsx'];

  // --- 1. Tool Integrity (Excessive Agency) ---
  const toolMatches = await grepFiles(src, [
    /tools\s*:\s*\[/i,
    /functions\s*:\s*\[/i,
    /new\s+DynamicTool/i,
    /new\s+StructuredTool/i,
    /@tool/i,
    /registry\.py/i // Pattern from agentic-chat
  ], { extensions: jsExtensions.concat(['.py']) });

  // --- 2. Prompt Injection (Insecure Concatenation & Wrapping) ---
  const promptMatches = await grepFiles(src, [
    /role\s*:\s*['"]system['"].*\$\{/i,
    /prompt\s*:\s*[`'].*\$\{.*[`']/i,
    /template\s*:\s*[`'].*\$\{.*[`']/i,
    /f"##.*json\.dumps/i, // Pattern from ExampleApp/agentic-chat
    /prompt_parts\.append/i,
    /"\s*\.join\(.*prompt_parts/i
  ], { extensions: jsExtensions.concat(['.py']) });

  if (promptMatches.length > 0) {
    findings.push({
      type: 'warning',
      title: 'Insecure prompt construction (Cascading/Concatenation)',
      description: 'Se detectó la construcción de prompts mediante concatenación de strings o wrapping de JSON sin delimitadores de seguridad. Esto es especialmente peligroso en sistemas multi-agente donde el output de un agente se convierte en el input del siguiente (Cascading Injection).',
      code_example: 'brief_message = f"## Brief\\n\\n```json\\n{json.dumps(brief)}\\n```" // Inseguro si "brief" tiene input de usuario',
      cve: null,
    });
  }

  // --- 3. Output Sanitization & Dangerous Sinks (SQL/API) ---
  const sinkMatchesRaw = await grepFiles(src, [
    /dangerouslySetInnerHTML/i,
    /eval\s*\(/i,
    /\bexec\s*\(/i,
    /innerHTML/i,
    /(?:UPDATE|SELECT|INSERT|DELETE).*(?:SET|WHERE|VALUES).*(?:\+|['"]\s*\+)/i, 
    /text\(f"UPDATE/i,
    /nanobana|image_client/i
  ], { extensions: jsExtensions.concat(['.py']), contextLines: 2 });

  // Filter out RegExp.exec() false positives
  const sinkMatches = sinkMatchesRaw.filter(m => {
    if (/\.exec\s*\(/.test(m.line) && /=.*\.exec\s*\(/.test(m.line)) return false; // regex.exec()
    return true;
  });

  if (sinkMatches.length > 0) {
    const locs = sinkMatches.slice(0, 3).map(m => `${path.basename(m.filePath)}:${m.lineNumber}`).join(', ');
    findings.push({
      type: 'critical',
      title: 'LLM-influenced data reaches dangerous sink (SQL/External API)',
      description: `Se detectó el uso de sinks peligrosos (SQL dinámico o APIs externas) en: ${locs}. Si estos datos provienen de un LLM, permite ataques de Indirect Prompt Injection.`,
      code_example: sinkMatches.slice(0, 2).map(m => `${path.basename(m.filePath)}:${m.lineNumber} → ${m.line.trim()}`).join('\n'),
      cve: null,
    });
  }

  // --- 4. SSRF via Agent tools ---
  const ssrfMatches = await grepFiles(src, [
    /url|uri|fetch|axios|http/i
  ], { extensions: jsExtensions });

  const isToolFile = (content) => /name\s*:\s*['"](fetch|url|browse|web)/i.test(content);
  for (const m of ssrfMatches) {
    const content = await readFile(m.filePath);
    if (isToolFile(content) && !/localhost|127\.0\.0\.1|169\.254/i.test(content)) {
       findings.push({
        type: 'vulnerability',
        title: 'Agent tool lacks SSRF protection',
        description: 'Una herramienta del agente parece realizar peticiones web sin validar contra IPs internas (localhost, metadatos de cloud). Esto permite ataques SSRF a través del LLM.',
        code_example: 'if (url.includes("169.254.169.254")) throw new Error("Access denied");',
        cve: null,
      });
      break;
    }
  }

  // --- 5. RAG / Data Leakage ---
  const ragMatches = await grepFiles(src, [
    /vectorStore/i,
    /pinecone|weaviate|milvus|chroma/i,
    /collection\.query/i
  ], { extensions: jsExtensions });

  if (ragMatches.length > 0) {
     const hasFilter = (await Promise.all(ragMatches.map(m => readFile(m.filePath)))).some(c => /filter|where|userId|tenantId/i.test(c));
     if (!hasFilter) {
       findings.push({
         type: 'vulnerability',
         title: 'RAG query without multi-tenant filtering',
         description: 'Se detectaron consultas a bases de datos vectoriales sin filtros de seguridad aparentes (userId/tenantId). Esto podría permitir que un usuario acceda a la "memoria" o documentos de otro usuario.',
         code_example: 'vectorStore.similaritySearch(query, 1, { filter: { userId: req.user.id } });',
         cve: null,
       });
     }
  }

  recommendations.push(
    'Usa esquemas JSON estrictos (enum, pattern) en todas las herramientas del agente.',
    'Aísla el input del usuario en los prompts usando delimitadores XML o Markdown.',
    'Sanitiza siempre la respuesta del LLM antes de renderizarla (usa DOMPurify).',
    'Implementa una denylist de IPs internas (SSRF) en las herramientas de navegación.',
    'Asegura que todas las búsquedas RAG incluyan un filtro por tenantId/userId.'
  );

  const vulnCount = findings.filter(f => f.type === 'vulnerability' || f.type === 'critical').length;
  const severity = vulnCount >= 2 ? 'critical' : vulnCount === 1 ? 'high' : findings.some(f => f.type === 'warning') ? 'medium' : 'ok';
  const score = Math.max(0, 100 - vulnCount * 20 - findings.filter(f => f.type === 'warning').length * 7);

  return { id: 'agentic', name: 'Agentic Security (LLM)', severity, score, findings, recommendations, _codeSnippets };
}

async function auditPython(src) {
  // Python equivalent scaffold... (to be expanded)
  return { id: 'agentic', name: 'Agentic Security (LLM)', severity: 'ok', score: 100, findings: [], recommendations: [], _codeSnippets: {} };
}

export async function audit(depth) {
  const { isPython, src, structure } = await detectProjectType();
  if (isPython) return auditPython(src);
  return auditNode(structure);
}

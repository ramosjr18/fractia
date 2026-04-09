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
  // Look for OpenAI tools/functions or LangChain tool definitions
  const toolMatches = await grepFiles(src, [
    /tools\s*:\s*\[/i,
    /functions\s*:\s*\[/i,
    /new\s+DynamicTool/i,
    /new\s+StructuredTool/i,
    /@tool/i
  ], { extensions: jsExtensions });

  if (toolMatches.length > 0) {
    const uniqueFiles = [...new Set(toolMatches.map(m => m.filePath))];
    for (const file of uniqueFiles) {
      const content = await readFile(file);
      if (content && !/enum|pattern|minimum|maximum/i.test(content)) {
        findings.push({
          type: 'vulnerability',
          title: `LLM Tools without strict parameter validation in ${path.basename(file)}`,
          description: 'Se detectaron definiciones de herramientas para LLM que no parecen usar restricciones de esquema (enum, pattern, min/max). Un atacante podría pasar valores arbitrarios (ej. rutas de archivos, comandos) si el modelo es manipulado.',
          code_example: '{\n  name: "read_file",\n  parameters: {\n    type: "object",\n    properties: { path: { type: "string" } } // Falta whitelist/pattern\n  }\n}',
          cve: null,
        });
        _codeSnippets[path.relative(src, file)] = truncate(content, 1000);
        break; 
      }
    }
  }

  // --- 2. Prompt Injection (Insecure Concatenation) ---
  const promptMatches = await grepFiles(src, [
    /role\s*:\s*['"]system['"].*\$\{/i,
    /prompt\s*:\s*[`'].*\$\{.*[`']/i,
    /template\s*:\s*[`'].*\$\{.*[`']/i
  ], { extensions: jsExtensions });

  if (promptMatches.length > 0) {
    findings.push({
      type: 'warning',
      title: 'Potential insecure prompt construction',
      description: 'Se detectó la construcción de prompts concatenando variables directamente. Sin delimitadores claros (ej. XML tags o markers tipo ###), el input del usuario puede desbordar las instrucciones del sistema (Prompt Injection).',
      code_example: 'const prompt = `System: do X. User input: ${userInput}`; // Inseguro\nconst prompt = `System: do X.\nUser: <input>${userInput}</input>`; // Mejor`,
      cve: null,
    });
  }

  // --- 3. Output Sanitization (LLM -> Sink) ---
  const outputMatches = await grepFiles(src, [
    /dangerouslySetInnerHTML/i,
    /eval\s*\(/i,
    /exec\s*\(/i,
    /innerHTML/i
  ], { extensions: jsExtensions });

  // Cross-reference with LLM response variables (crude check)
  if (outputMatches.length > 0) {
    const llmVarMatches = await grepFiles(src, [/choices\[0\]\.message/, /response\.content/, /aiResponse/], { extensions: jsExtensions });
    if (llmVarMatches.length > 0) {
      findings.push({
        type: 'critical',
        title: 'LLM output potentially passed to dangerous sink',
        description: 'Se detectó el uso de sinks peligrosos (eval, innerHTML) en el mismo proyecto que usa LLMs. Si la respuesta del modelo no se sanitiza, un atacante puede ejecutar XSS o RCE inyectando código en la respuesta de la IA.',
        code_example: '<div dangerouslySetInnerHTML={{ __html: aiResponse }} />',
        cve: null,
      });
    }
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

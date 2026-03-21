import OpenAI from 'openai';
import { config } from '../config.js';
import { truncate, discoverStructure } from './fileScanner.js';

const MAX_SNIPPET_LENGTH = 1500;
const MAX_TOTAL_CONTEXT  = 8000;

/**
 * Enrich static analysis findings with OpenAI analysis of the REAL code.
 * Only called in deep/full modes when OPENAI_API_KEY is set.
 * Mutates findings in-place by appending AI-discovered items.
 */
export async function enrichWithOpenAI(auditResults, depth) {
  if (!config.openaiApiKey) return;

  const client = new OpenAI({ apiKey: config.openaiApiKey });

  // Collect code snippets from auditors that have them
  const snippetParts = [];
  let totalLen = 0;

  for (const result of auditResults) {
    if (!result._codeSnippets || Object.keys(result._codeSnippets).length === 0) continue;
    for (const [filePath, code] of Object.entries(result._codeSnippets)) {
      const snippet = truncate(code, MAX_SNIPPET_LENGTH);
      const part = `### [${result.name}] ${filePath}\n\`\`\`javascript\n${snippet}\n\`\`\`\n`;
      totalLen += part.length;
      if (totalLen > MAX_TOTAL_CONTEXT) break;
      snippetParts.push(part);
    }
    if (totalLen > MAX_TOTAL_CONTEXT) break;
  }

  if (snippetParts.length === 0) return;

  const confirmedFindings = auditResults
    .flatMap(r => r.findings.map(f => `[${r.name}] ${f.type.toUpperCase()}: ${f.title}`))
    .join('\n');

  const isFullPentest = depth === 'full';
  const structure = await discoverStructure();

  const prompt = `You are a senior application security engineer (AppSec) performing a code review.

## Project structure:
Framework: ${structure.framework}
Source root: ${structure.srcDir}
Available modules: ${Object.keys(structure.dirs).join(', ')}

## Already confirmed by static analysis:
${confirmedFindings}

## Actual source code of critical files:
${snippetParts.join('\n')}

## Your task:
${isFullPentest
  ? `1. Identify additional vulnerabilities NOT yet listed above that are specific to this code.
2. Build concrete ATTACK CHAINS that combine multiple confirmed findings (e.g. "JWT fallback → forge any user token → no cross-tenant check → read all tenant data").
3. For each attack chain, describe the exact steps an attacker would take.
4. Provide prioritized remediation with specific code changes.`
  : `1. Identify additional vulnerabilities NOT yet listed above that are specific to this code.
2. For each confirmed CRITICAL/HIGH finding, explain the realistic exploit scenario.
3. Provide specific, actionable remediation with code examples.`
}

Return a JSON array of additional findings to append. Each element:
{
  "moduleId": "<module id from the list: auth|api|ddos|sql|xss|secrets|headers|deps|infra|bots|crypto|logs>",
  "finding": {
    "type": "vulnerability|warning|info",
    "title": "Short title",
    "description": "Technical description referencing the specific code above",
    "code_example": "Vulnerable code snippet or null",
    "cve": "CVE-XXXX-XXXX or null"
  }
}

Return ONLY the JSON array, no markdown.`;

  try {
    const completion = await client.chat.completions.create({
      model: 'gpt-4o',
      max_tokens: 2500,
      messages: [{ role: 'user', content: prompt }],
    });

    const raw = (completion.choices[0]?.message?.content || '').trim();
    const parsed = JSON.parse(raw.replace(/^```json|```$/gm, '').trim());

    if (!Array.isArray(parsed)) return;

    for (const item of parsed) {
      const target = auditResults.find(r => r.id === item.moduleId);
      if (target && item.finding) {
        target.findings.push({ ...item.finding, _aiGenerated: true });
      }
    }
  } catch (err) {
    console.warn('[openaiClient] Enrichment failed:', err.message);
  }
}

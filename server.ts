import express from 'express';
import path from 'path';
import { fileURLToPath } from 'url';
import dotenv from 'dotenv';
import { GoogleGenAI } from '@google/genai';

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const PORT = Number(process.env.PORT) || 3000;
const isProduction = process.env.NODE_ENV === 'production';

function getGeminiClient(): GoogleGenAI {
  const apiKey = process.env.GEMINI_API_KEY;
  if (!apiKey) {
    throw new Error('GEMINI_API_KEY is not configured in server secrets.');
  }
  return new GoogleGenAI({
    apiKey,
    httpOptions: {
      headers: {
        'User-Agent': 'aistudio-build',
      },
    },
  });
}

function extractJsonPayload(rawText: string): Record<string, unknown> {
  const trimmed = rawText.trim();
  const fencedMatch = trimmed.match(/```(?:json)?\s*([\s\S]*?)```/i);
  const candidate = fencedMatch ? fencedMatch[1].trim() : trimmed;
  const firstBrace = candidate.indexOf('{');
  const lastBrace = candidate.lastIndexOf('}');
  if (firstBrace === -1 || lastBrace === -1 || lastBrace <= firstBrace) {
    throw new Error('Model response did not contain a valid JSON object.');
  }
  return JSON.parse(candidate.slice(firstBrace, lastBrace + 1)) as Record<string, unknown>;
}

const ALLOWED_MEDIA_MIMES = new Set([
  'image/png',
  'image/jpeg',
  'image/webp',
  'image/gif',
  'audio/mpeg',
  'audio/mp3',
  'audio/wav',
  'audio/ogg',
  'audio/flac',
  'video/mp4',
  'video/webm',
]);

async function startServer() {
  const app = express();
  app.use(express.json({ limit: '12mb' }));

  app.get('/api/health', (_req, res) => {
    res.json({ status: 'ok', hasKey: Boolean(process.env.GEMINI_API_KEY) });
  });

  app.post('/api/forensics/analyze', async (req, res) => {
    try {
      const { inputType, content, mediaBase64, mimeType, fileName } = req.body ?? {};

      if (typeof inputType !== 'string' || !['url', 'text', 'media'].includes(inputType)) {
        return res.status(400).json({ error: 'Invalid inputType. Must be url, text, or media.' });
      }

      const textContent = typeof content === 'string' ? content.trim() : '';

      if (inputType !== 'media' && textContent.length < 4) {
        return res.status(400).json({ error: 'Please provide a URL or claim text with at least 4 characters.' });
      }

      if (textContent.length > 8000) {
        return res.status(400).json({ error: 'Input text exceeds 8,000 character limit.' });
      }

      if (inputType === 'media') {
        if (typeof mediaBase64 !== 'string' || mediaBase64.length === 0) {
          return res.status(400).json({ error: 'Please attach an image, audio, or video sample to analyze.' });
        }
        if (typeof mimeType !== 'string' || !ALLOWED_MEDIA_MIMES.has(mimeType)) {
          return res.status(400).json({ error: 'Unsupported media MIME type.' });
        }
        if (mediaBase64.length > 10_500_000) {
          return res.status(400).json({ error: 'Media payload exceeds 8MB limit.' });
        }
      }

      const ai = getGeminiClient();

      const forensicInstruction = `You are VeritasAI, an expert digital forensics, OSINT fact-checking, and media authenticity analyst.
Analyze the submitted ${inputType === 'media' ? 'media artifact' : inputType === 'url' ? 'URL / social post reference' : 'claim or transcript'}.
${inputType !== 'media' ? 'Use Google Search grounding to cross-verify factual claims against reputable wires, official institutions, and fact-checkers.' : 'Inspect visual/audio cues for signs of AI synthesis, manipulation, splicing, lighting/boundary inconsistencies, or authentic capture provenance.'}

Return ONLY a valid JSON object matching this exact structure (no markdown commentary outside JSON):
{
  "headline": "Concise 8-14 word summary of the claim or media subject",
  "claimText": "Exact or cleaned claim/artifact statement under inspection",
  "category": "One of: Fabrication Incident | Peer-Reviewed Signal | Manipulated Footage | Verified Claim | Synthetic Media",
  "radarCategory": "One of: health | geopolitics | finance | elections",
  "threatLevel": "One of: critical | amber | verified",
  "verdictTitle": "Short uppercase verdict e.g. FABRICATED MISINFORMATION or VERIFIED AUTHENTIC or CONTEXT COMPROMISED",
  "verdictSubtitle": "Short technical subtitle e.g. Synthetic Origin Detected • Critical Threat Level",
  "truthIndex": 18,
  "authenticityPct": 14.5,
  "syntheticProbPct": 86.2,
  "factConsensusPct": 95,
  "spreadLabel": "VIRAL SPREAD: HIGH or CRYPTOGRAPHIC CERTIFIED or CONTEXT COMPROMISED",
  "overlayTelemetry": "Short 4-6 word HUD readout e.g. Semantic Anomaly: 86.2% or Primary Wire Confirmed",
  "sourcePlatform": "Platform or origin label e.g. X (Twitter), TikTok, Direct Media Upload",
  "summary": "2-3 sentence concise forensic summary citing concrete verification findings.",
  "tags": [
    { "label": "Short finding tag 1", "tone": "error | amber | verified | neutral", "icon": "warning | verified | dns | mic_off | fact_check | psychology" },
    { "label": "Short finding tag 2", "tone": "error | amber | verified | neutral", "icon": "hub | fingerprint | schedule | travel_explore" },
    { "label": "Short finding tag 3", "tone": "error | amber | verified | neutral", "icon": "fact_check | security | shield" }
  ],
  "stylometric": {
    "summary": "Brief assessment of phrasing, perplexity, or visual/structural entropy",
    "perplexity": "e.g. 14.2 (Low Entropy) or 68.4 (Natural)",
    "burstiness": "e.g. 0.21 or 0.74",
    "tokens": [
      { "text": "Segment 1 of claim ", "flagged": false },
      { "text": "highlighted phrase", "flagged": true },
      { "text": " remainder of claim.", "flagged": false }
    ]
  },
  "provenance": {
    "signatureStatus": "e.g. MISSING (Unsigned) or C2PA VALIDATED",
    "renderEngine": "e.g. Unknown / Social Re-encode or Canon EOS R5",
    "anomalyNote": "1-sentence provenance and metadata observation",
    "propagationVelocity": "e.g. 12.4k shares/hour or Organic Wire"
  },
  "attributionNodes": [
    { "step": "Genesis Node", "time": "T+00:00", "actor": "Source platform or uploader", "detail": "Initial detection vector" },
    { "step": "Propagation", "time": "T+00:35", "actor": "Secondary relays", "detail": "Cross-platform distribution pattern" },
    { "step": "Verification", "time": "T+01:10", "actor": "VeritasAI Consensus", "detail": "Cross-checked against authoritative feeds" }
  ],
  "counterEvidence": [
    { "source": "Authoritative Source Name", "tag": "OFFICIAL RECORD or FACT CHECK", "quote": "Concise factual finding or disavowal." }
  ],
  "labMetrics": {
    "spatialScore": 84,
    "temporalScore": 79,
    "audioSyncScore": 72,
    "spectralScore": 88
  }
}`;

      const startTime = Date.now();

      let response;
      if (inputType === 'media') {
        response = await ai.models.generateContent({
          model: 'gemini-4-hydrogen',
          contents: {
            parts: [
              {
                inlineData: {
                  mimeType,
                  data: mediaBase64,
                },
              },
              {
                text: `${forensicInstruction}\n\nUploaded file name: ${typeof fileName === 'string' ? fileName : 'media_sample'}.\nAdditional analyst context: ${textContent || 'Perform full deepfake, manipulation, and authenticity inspection on this uploaded media.'}`,
              },
            ],
          },
          config: {
            responseMimeType: 'application/json',
          },
        });
      } else {
        response = await ai.models.generateContent({
          model: 'gemini-4-hydrogen',
          contents: `${forensicInstruction}\n\nSubmitted ${inputType.toUpperCase()} target:\n${textContent}`,
          config: {
            tools: [{ googleSearch: {} }],
          },
        });
      }

      const latencyMs = Date.now() - startTime;
      const rawText = response.text;
      if (!rawText) {
        return res.status(502).json({ error: 'Gemini returned an empty forensic analysis response.' });
      }

      const parsed = extractJsonPayload(rawText);

      const rawChunks = response.candidates?.[0]?.groundingMetadata?.groundingChunks ?? [];
      const groundingSources = rawChunks
        .map((chunk: { web?: { uri?: string; title?: string } }) => chunk.web)
        .filter((w): w is { uri: string; title?: string } => Boolean(w?.uri))
        .slice(0, 6)
        .map((w) => ({
          title: w.title || w.uri,
          uri: w.uri,
        }));

      return res.json({
        analysis: parsed,
        groundingSources,
        latencyMs,
      });
    } catch (error) {
      const message = error instanceof Error ? error.message : 'Forensic analysis failed.';
      console.error('Error in /api/forensics/analyze:', message);
      return res.status(500).json({ error: message });
    }
  });

  app.post('/api/forensics/reverse-search', async (req, res) => {
    try {
      const { query } = req.body ?? {};
      if (typeof query !== 'string' || query.trim().length < 3) {
        return res.status(400).json({ error: 'Provide a search query of at least 3 characters.' });
      }
      if (query.length > 1000) {
        return res.status(400).json({ error: 'Query exceeds 1,000 character limit.' });
      }

      const ai = getGeminiClient();
      const response = await ai.models.generateContent({
        model: 'gemini-4-hydrogen',
        contents: `Perform an OSINT reverse origin and authoritative wire verification search for this claim or media description. Summarize earliest known origin, authoritative fact-checks, and manipulation history in 3 concise bullet points:\n\n${query.trim()}`,
        config: {
          tools: [{ googleSearch: {} }],
        },
      });

      const rawChunks = response.candidates?.[0]?.groundingMetadata?.groundingChunks ?? [];
      const sources = rawChunks
        .map((chunk: { web?: { uri?: string; title?: string } }) => chunk.web)
        .filter((w): w is { uri: string; title?: string } => Boolean(w?.uri))
        .slice(0, 6)
        .map((w) => ({
          title: w.title || w.uri,
          uri: w.uri,
        }));

      return res.json({
        summary: response.text || 'No additional external provenance records found.',
        sources,
      });
    } catch (error) {
      const message = error instanceof Error ? error.message : 'Reverse origin search failed.';
      console.error('Error in /api/forensics/reverse-search:', message);
      return res.status(500).json({ error: message });
    }
  });

  if (isProduction) {
    const distDir = path.resolve(__dirname, 'dist');
    app.use(express.static(distDir));
    app.get('*', (_req, res) => {
      res.sendFile(path.join(distDir, 'index.html'));
    });
  } else {
    const { createServer: createViteServer } = await import('vite');
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  }

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`VeritasAI server running at http://0.0.0.0:${PORT}`);
  });
}

startServer().catch((err) => {
  console.error('Failed to start VeritasAI server:', err);
  process.exit(1);
});

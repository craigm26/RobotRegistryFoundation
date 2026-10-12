/**
 * The method text's exact bytes, the file its SHA-256 identifies. Read from the vendored copy at
 * build time (the build runs from the repository root); tests/bounded-embodiment.test.ts checks
 * the copy's hash, and the deploy workflow checks the built file's.
 */
import type { APIRoute } from 'astro';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';

export const GET: APIRoute = () =>
  new Response(readFileSync(join(process.cwd(), 'src/data/bounded-embodiment/method-v0.1.md')), {
    headers: { 'Content-Type': 'text/markdown; charset=utf-8' },
  });

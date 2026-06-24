'use server';

import { exec } from 'child_process';
import { promisify } from 'util';
import path from 'path';
import fs from 'fs';

const execAsync = promisify(exec);
const ORACLE_BIN = path.resolve(process.cwd(), '../target/debug/oracle.exe');
const INVESTIGATIONS_DIR = path.resolve(process.cwd(), '../investigations');

export async function runDoctor(): Promise<{success: boolean; output: string}> {
  try {
    const { stdout, stderr } = await execAsync(`"${ORACLE_BIN}" doctor`, { cwd: path.resolve(process.cwd(), '..') });
    return { success: true, output: stdout + stderr };
  } catch (error: any) {
    return { success: false, output: error.stdout || error.stderr || error.message };
  }
}

export async function listCases(): Promise<{success: boolean; cases: CaseInfo[]}> {
  try {
    const entries = fs.existsSync(INVESTIGATIONS_DIR) 
      ? fs.readdirSync(INVESTIGATIONS_DIR, { withFileTypes: true })
        .filter(d => d.isDirectory() && d.name.match(/^[0-9a-f]{8}-/))
        .map(d => {
          const casePath = path.join(INVESTIGATIONS_DIR, d.name);
          const stat = fs.statSync(casePath);
          const files = fs.readdirSync(casePath);
          return {
            id: d.name,
            name: `Investigation ${d.name.slice(0, 8)}`,
            artifactCount: files.length,
            lastModified: stat.mtime.toISOString(),
            path: casePath,
          };
        })
      : [];
    return { success: true, cases: entries };
  } catch (error: any) {
    return { success: false, cases: [] };
  }
}

export async function createCase(caseName: string, examiner: string): Promise<{success: boolean; output: string; investigationId?: string}> {
  try {
    const { stdout, stderr } = await execAsync(
      `"${ORACLE_BIN}" case new --case-name "${caseName}" --examiner "${examiner}"`,
      { cwd: path.resolve(process.cwd(), '..') }
    );
    const combined = stdout + stderr;
    const idMatch = combined.match(/Investigation ID:\s*([0-9a-f-]+)/);
    return { 
      success: true, 
      output: combined,
      investigationId: idMatch ? idMatch[1] : undefined,
    };
  } catch (error: any) {
    return { success: false, output: error.stdout || error.stderr || error.message };
  }
}

export async function verifyAudit(investigationId: string): Promise<{success: boolean; output: string}> {
  try {
    const { stdout, stderr } = await execAsync(
      `"${ORACLE_BIN}" verify-audit --investigation-id "${investigationId}"`,
      { cwd: path.resolve(process.cwd(), '..') }
    );
    return { success: true, output: stdout + stderr };
  } catch (error: any) {
    return { success: false, output: error.stdout || error.stderr || error.message };
  }
}

export interface CaseInfo {
  id: string;
  name: string;
  artifactCount: number;
  lastModified: string;
  path: string;
}

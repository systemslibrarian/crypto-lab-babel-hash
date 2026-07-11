declare module '*.css';

declare module '@noble/hashes/blake3.js' {
  export function blake3(data: Uint8Array): Uint8Array;
}

declare module 'vitest' {
  export const describe: (name: string, fn: () => void) => void;
  export const it: {
    (name: string, fn: () => void | Promise<void>): void;
    each: <T>(cases: readonly T[]) => (name: string, fn: (testCase: T) => void | Promise<void>) => void;
  };
  export const beforeAll: (fn: () => void | Promise<void>) => void;
  export const afterAll: (fn: () => void | Promise<void>) => void;
  export const expect: {
    (value: unknown): {
      toBe: (expected: unknown) => void;
      toEqual: (expected: unknown) => void;
      toHaveLength: (expected: number) => void;
      toBeGreaterThan: (expected: number) => void;
      toBeGreaterThanOrEqual: (expected: number) => void;
      toBeLessThan: (expected: number) => void;
      toBeLessThanOrEqual: (expected: number) => void;
      toBeNull: () => void;
      toContain: (expected: unknown) => void;
      toThrow: (expected?: unknown) => void;
      toMatchObject: (expected: object) => void;
      not: {
        toBe: (expected: unknown) => void;
        toBeNull: () => void;
      };
      resolves: {
        toBe: (expected: unknown) => Promise<void>;
        toMatchObject: (expected: object) => Promise<void>;
      };
    };
  };
}

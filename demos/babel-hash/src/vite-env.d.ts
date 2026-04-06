declare module '*.css';

declare module '@noble/hashes/blake3.js' {
  export function blake3(data: Uint8Array): Uint8Array;
}

declare module 'vitest' {
  export const describe: (name: string, fn: () => void) => void;
  export const it: (name: string, fn: () => void | Promise<void>) => void;
  export const expect: {
    (value: unknown): {
      toBe: (expected: unknown) => void;
      toEqual: (expected: unknown) => void;
      toHaveLength: (expected: number) => void;
      toBeGreaterThan: (expected: number) => void;
      toBeLessThan: (expected: number) => void;
      toMatchObject: (expected: object) => void;
      not: {
        toBe: (expected: unknown) => void;
      };
      resolves: {
        toBe: (expected: unknown) => Promise<void>;
        toMatchObject: (expected: object) => Promise<void>;
      };
    };
  };
}

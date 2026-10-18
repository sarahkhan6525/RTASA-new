// A small local "demo credential vault" -- this app runs entirely on your
// own machine (Vite dev server + your FastAPI backend), so remembering a
// role's demo passphrase in the browser's localStorage between pages
// (Protect Record -> Access Requests) is just a convenience, not a
// security boundary: these are demo credentials for a local prototype,
// never anything the backend treats as a real secret (private keys never
// leave the backend at all). Lets a live demo move between pages without
// re-typing four random passphrases from memory.

const KEY = "rtasa_demo_credentials_v1";

type Store = Record<string, string>; // role_id -> passphrase

function readStore(): Store {
  try {
    const raw = localStorage.getItem(KEY);
    return raw ? JSON.parse(raw) : {};
  } catch {
    return {};
  }
}

function writeStore(store: Store) {
  try {
    localStorage.setItem(KEY, JSON.stringify(store));
  } catch {
    /* ignore -- demo convenience only */
  }
}

export function saveCredential(roleId: string, passphrase: string) {
  const store = readStore();
  store[roleId] = passphrase;
  writeStore(store);
}

export function getCredential(roleId: string): string | null {
  return readStore()[roleId] ?? null;
}

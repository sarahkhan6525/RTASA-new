// UTF-8-safe base64 for text, plus a real ArrayBuffer path for uploaded
// files (so a non-text file isn't mangled going through btoa).

export function textToBase64(str: string): string {
  return btoa(encodeURIComponent(str).replace(/%([0-9A-F]{2})/g, (_, p) => String.fromCharCode(parseInt(p, 16))));
}

export function fileToBase64(file: File): Promise<string> {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => {
      const result = reader.result as string; // data:<mime>;base64,<data>
      const comma = result.indexOf(",");
      resolve(result.slice(comma + 1));
    };
    reader.onerror = () => reject(reader.error);
    reader.readAsDataURL(file);
  });
}

// A random demo credential -- not a cryptographic secret in the "private
// key" sense, just the passphrase a role holder would type in later to
// act as that role (same idea as `rtasa`'s own demo scripts). Satisfies
// the backend's >=12-char policy with plenty of margin.
export function generateDemoPassphrase(): string {
  const words = ["violet", "harbor", "kernel", "copper", "lagoon", "ember", "granite", "willow", "cobalt", "ridge"];
  const pick = () => words[Math.floor(Math.random() * words.length)];
  const num = Math.floor(1000 + Math.random() * 9000);
  return `${pick()}-${pick()}-${num}`;
}

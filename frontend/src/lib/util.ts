// UTF-8-safe base64 for text, plus a real ArrayBuffer path for uploaded
// files (so a non-text file isn't mangled going through btoa).

export function textToBase64(str: string): string {
  return btoa(encodeURIComponent(str).replace(/%([0-9A-F]{2})/g, (_, p) => String.fromCharCode(parseInt(p, 16))));
}

// Internal: an 8-byte ASCII magic marker + a 2-byte big-endian length +
// the filename's UTF-8 bytes, prepended to a file's raw bytes before it's
// sent. The backend/DB never know this header exists -- to them it's just
// more of "the message" being encrypted -- so the original filename and
// extension survive the full encrypt/store/decrypt round trip with no
// schema change anywhere. RequesterPortal.tsx's stripFileHeader() is the
// other end of this: it looks for the same magic marker and, if found,
// pulls the filename back out before handing the rest to the user as the
// downloaded file.
const FILE_HEADER_MAGIC = "RTASAFN1"; // 8 ASCII bytes, checked verbatim on the other end

function utf8BytesAsBinaryString(str: string): string {
  // Same trick textToBase64 uses, stopped one step short of btoa so the
  // raw UTF-8 bytes can be concatenated with the file's own bytes first.
  return encodeURIComponent(str).replace(/%([0-9A-F]{2})/g, (_, p) => String.fromCharCode(parseInt(p, 16)));
}

export function fileToBase64(file: File): Promise<string> {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => {
      const result = reader.result as string; // data:<mime>;base64,<data>
      const comma = result.indexOf(",");
      const rawBase64 = result.slice(comma + 1);

      const nameBytes = utf8BytesAsBinaryString(file.name);
      if (nameBytes.length > 0xffff) {
        // An absurdly long filename -- bail out and send the file exactly
        // as before rather than risk corrupting the length field below.
        resolve(rawBase64);
        return;
      }
      const header =
        FILE_HEADER_MAGIC +
        String.fromCharCode((nameBytes.length >> 8) & 0xff, nameBytes.length & 0xff) +
        nameBytes;
      // atob/btoa round-trip the file's own bytes byte-for-byte; only the
      // header bytes in front of them are new.
      resolve(btoa(header + atob(rawBase64)));
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

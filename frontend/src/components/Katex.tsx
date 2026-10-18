// Thin wrapper around KaTeX for rendering the paper's actual equations
// as real typeset math (superscripts, subscripts, sums, products) --
// not plain-text approximations like "x_i^j".
import { useMemo } from "react";
import katex from "katex";

interface Props {
  tex: string;
  display?: boolean;
  className?: string;
}

export default function Katex({ tex, display = false, className }: Props) {
  const html = useMemo(() => {
    try {
      return katex.renderToString(tex, {
        throwOnError: false,
        displayMode: display,
        output: "html",
      });
    } catch {
      return tex;
    }
  }, [tex, display]);

  // eslint-disable-next-line react/no-danger
  return <span className={className} dangerouslySetInnerHTML={{ __html: html }} />;
}

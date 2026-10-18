interface Props {
  title: string;
}

export default function ComingNext({ title }: Props) {
  return (
    <div className="flex h-full min-h-[300px] flex-col items-center justify-center rounded-2xl border border-dashed border-slate-800 bg-slate-900/30 text-center">
      <div className="text-lg font-semibold text-slate-300">{title}</div>
      <p className="mt-2 max-w-sm text-sm text-slate-500">
        Not built yet -- this page is next in line, wired to the real backend when it's built,
        same as the Dashboard.
      </p>
    </div>
  );
}

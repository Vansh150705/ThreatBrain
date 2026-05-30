function App() {
  return (
    <div className="min-h-screen bg-slate-50 flex items-center justify-center p-6">
      <div className="max-w-2xl w-full">
        <div className="bg-white rounded-2xl shadow-xl border border-slate-200 p-10">
          <div className="flex items-center gap-3 mb-6">
            <div className="w-10 h-10 rounded-lg bg-primary-600 flex items-center justify-center text-white font-bold text-lg">
              T
            </div>
            <div>
              <h1 className="text-2xl font-bold text-slate-900">
                ThreatBrain
              </h1>
              <p className="text-sm text-slate-500">The Neural SOC</p>
            </div>
          </div>

          <p className="text-slate-700 leading-relaxed mb-6">
            Frontend foundation is live. Tailwind v4 design tokens active,
            Inter font loaded, primary palette ready.
          </p>

          <div className="grid grid-cols-5 gap-2 mb-6">
            <div className="aspect-square bg-severity-info rounded-md flex items-center justify-center text-white text-xs font-medium">
              info
            </div>
            <div className="aspect-square bg-severity-low rounded-md flex items-center justify-center text-white text-xs font-medium">
              low
            </div>
            <div className="aspect-square bg-severity-medium rounded-md flex items-center justify-center text-white text-xs font-medium">
              med
            </div>
            <div className="aspect-square bg-severity-high rounded-md flex items-center justify-center text-white text-xs font-medium">
              high
            </div>
            <div className="aspect-square bg-severity-critical rounded-md flex items-center justify-center text-white text-xs font-medium">
              crit
            </div>
          </div>

          <div className="flex gap-3">
            <button className="px-5 py-2.5 rounded-lg bg-primary-600 text-white font-medium hover:bg-primary-700 transition-colors">
              Primary Action
            </button>
            <button className="px-5 py-2.5 rounded-lg bg-white border border-slate-300 text-slate-700 font-medium hover:bg-slate-50 transition-colors">
              Secondary
            </button>
          </div>
        </div>

        <p className="text-center text-sm text-slate-400 mt-6 font-mono">
          step 5.2 ✓ tailwind v4 + design tokens
        </p>
      </div>
    </div>
  );
}

export default App;
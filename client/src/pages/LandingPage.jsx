import React, { Suspense, lazy, useState } from "react";
import {
  ShieldAlert, ArrowRight, Activity, Cpu, Lock
} from "lucide-react";

// Lazy-load Spline to prevent blocking initial page render
const Spline = lazy(() => import("@splinetool/react-spline"));

const SPLINE_ROBOT_SCENE = "https://prod.spline.design/kZDDjO5HuC9GJUM2/scene.splinecode";

export default function LandingPage({ onGetStarted }) {
  const [isSceneLoaded, setIsSceneLoaded] = useState(false);

  return (
    <div className="min-h-screen bg-[#060913] text-slate-100 flex flex-col relative overflow-hidden cyber-grid font-sans selection:bg-cyan-500/30 selection:text-cyan-200">
      {/* Background ambient lighting glows */}
      <div className="absolute top-1/4 -left-32 w-96 h-96 bg-cyan-500/10 rounded-full blur-[120px] pointer-events-none" />
      <div className="absolute top-1/3 -right-32 w-96 h-96 bg-indigo-600/10 rounded-full blur-[140px] pointer-events-none" />
      <div className="absolute bottom-10 left-1/3 w-80 h-80 bg-purple-600/5 rounded-full blur-[100px] pointer-events-none" />

      {/* Top Header */}
      <header className="relative z-20 border-b border-slate-800/60 bg-[#080b12]/80 backdrop-blur-md px-6 lg:px-12 py-4 flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="relative shrink-0">
            <ShieldAlert className="h-7 w-7 text-cyan-400" />
            <div className="absolute inset-0 bg-cyan-400 rounded-md blur-md opacity-30 animate-pulse" />
          </div>
          <div>
            <span className="text-base font-extrabold tracking-wider text-transparent bg-clip-text bg-gradient-to-r from-white via-cyan-300 to-indigo-300 font-mono-tech">
              CYBERFORECASTER
            </span>
          </div>
        </div>

        <div className="flex items-center gap-4">
          <div className="hidden sm:flex items-center gap-2 bg-slate-900/80 border border-slate-800 px-3 py-1.5 rounded-full text-[10px] font-mono-tech text-cyan-400">
            <span className="h-2 w-2 rounded-full bg-cyan-400 animate-ping" />
            <span>AI SENSORS ACTIVE</span>
          </div>
          <button
            onClick={onGetStarted}
            className="text-xs font-mono-tech uppercase tracking-wider text-slate-300 hover:text-cyan-300 transition-colors px-3 py-1.5 border border-slate-700/60 hover:border-cyan-500/50 rounded-md bg-slate-900/60 hover:bg-cyan-950/20"
          >
            Open Dashboard
          </button>
        </div>
      </header>

      {/* Main Two-Column Hero Section */}
      <main className="flex-1 flex items-center relative z-10 px-6 sm:px-10 lg:px-16 py-8 lg:py-0 max-w-7xl mx-auto w-full">
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-8 lg:gap-12 items-center w-full min-h-[calc(100vh-140px)]">
          
          {/* LEFT SIDE: Project Name, Tagline, Description, CTA */}
          <div className="lg:col-span-6 flex flex-col justify-center text-left space-y-6 z-20">
            
            {/* System Identifier Badge */}
            <div className="inline-flex items-center gap-2 px-3 py-1.5 rounded-md bg-cyan-950/30 border border-cyan-500/30 text-cyan-300 text-xs font-mono-tech w-fit">
              <Activity className="h-3.5 w-3.5 text-cyan-400 animate-pulse" />
              <span className="tracking-widest uppercase">CyberForecaster</span>
            </div>

            {/* Main Headline / Tagline */}
            <h1 className="text-4xl sm:text-5xl lg:text-6xl font-black tracking-tight leading-[1.1] text-white">
              See the Attack{" "}
              <span className="text-transparent bg-clip-text bg-gradient-to-r from-cyan-300 via-sky-300 to-indigo-400">
                Before It Happens
              </span>
            </h1>

            {/* Supporting Text */}
            <p className="text-sm sm:text-base text-slate-300 leading-relaxed font-normal max-w-xl">
              Stay ahead of cyber threats with intelligent insights from your network.
            </p>

            {/* Call To Action Button */}
            <div className="pt-2">
              <button
                id="get-started-btn"
                onClick={onGetStarted}
                className="group relative inline-flex items-center justify-center gap-3 px-8 py-4 rounded-lg text-sm sm:text-base font-mono-tech font-bold uppercase tracking-wider text-black bg-gradient-to-r from-cyan-400 via-cyan-300 to-sky-400 border border-cyan-300 hover:border-cyan-200 shadow-[0_0_20px_rgba(0,240,255,0.25)] hover:shadow-[0_0_35px_rgba(0,240,255,0.5)] transition-all duration-300 ease-out hover:scale-[1.02] active:scale-[0.98] cursor-pointer"
              >
                <span>GET STARTED</span>
                <ArrowRight className="h-4 w-4 text-black group-hover:translate-x-1 transition-transform duration-300" />
                <div className="absolute inset-0 rounded-lg bg-white/20 opacity-0 group-hover:opacity-100 transition-opacity duration-300 pointer-events-none" />
              </button>
            </div>

            {/* Subtle Tech Indicators */}
            <div className="pt-4 border-t border-slate-800/60 grid grid-cols-2 gap-4 max-w-md text-xs font-mono-tech text-slate-400">
              <div className="flex items-center gap-2">
                <Cpu className="h-3.5 w-3.5 text-cyan-400" />
                <span>PyTorch GRU Forecasting</span>
              </div>
              <div className="flex items-center gap-2">
                <Lock className="h-3.5 w-3.5 text-indigo-400" />
                <span>Evidence-Supported Assessment</span>
              </div>
            </div>

          </div>

          {/* RIGHT SIDE: Spline 3D Robot (Clean, Borderless Presentation) */}
          <div className="lg:col-span-6 w-full h-[420px] sm:h-[500px] lg:h-[620px] relative flex items-center justify-center">
            
            {/* Ambient Backlight for 3D Robot */}
            <div className="absolute inset-0 bg-gradient-to-t from-cyan-500/10 via-indigo-500/5 to-transparent rounded-2xl blur-xl pointer-events-none" />
            
            {/* Robot Direct Container */}
            <div className="w-full h-full relative flex items-center justify-center">
              
              {/* Loading skeleton / Fallback */}
              {!isSceneLoaded && (
                <div className="absolute inset-0 flex flex-col items-center justify-center text-center p-4">
                  <div className="h-10 w-10 border-2 border-cyan-400/30 border-t-cyan-400 rounded-full animate-spin mb-3" />
                  <p className="text-xs font-mono-tech text-cyan-300 tracking-wider">
                    INITIALIZING 3D ROBOT...
                  </p>
                </div>
              )}

              {/* Spline 3D Scene */}
              <Suspense
                fallback={
                  <div className="w-full h-full flex items-center justify-center">
                    <div className="h-8 w-8 border-2 border-cyan-400/30 border-t-cyan-400 rounded-full animate-spin" />
                  </div>
                }
              >
                <Spline
                  scene={SPLINE_ROBOT_SCENE}
                  onLoad={() => setIsSceneLoaded(true)}
                  className="w-full h-full cursor-grab active:cursor-grabbing"
                />
              </Suspense>

            </div>
          </div>

        </div>
      </main>

      {/* Minimal Footer */}
      <footer className="relative z-20 border-t border-slate-800/50 bg-[#080b12]/60 px-6 py-3 text-center text-[10px] font-mono-tech text-slate-500 flex flex-wrap justify-between items-center max-w-7xl mx-auto w-full">
        <div>
          <span>CyberForecaster // AI Network Attack Forecasting</span>
        </div>
        <div className="flex items-center gap-4">
          <span>10 Chronological 5s Windows</span>
          <span>•</span>
          <span>14 Flow Features</span>
        </div>
      </footer>
    </div>
  );
}

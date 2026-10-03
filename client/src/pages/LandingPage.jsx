import React, { Suspense, lazy, useState } from "react";
import {
  ArrowRight, Cpu, Lock
} from "lucide-react";

// Lazy-load Spline to prevent blocking initial page render
const Spline = lazy(() => import("@splinetool/react-spline"));

// The 3D scene is stored in client/public so the home page works offline.
const SPLINE_ROBOT_SCENE = "/robot.splinecode";

export default function LandingPage({ onGetStarted }) {
  const [isSceneLoaded, setIsSceneLoaded] = useState(false);

  return (
    <div className="h-screen min-h-screen bg-bg text-text flex flex-col justify-center relative overflow-hidden cyber-grid font-sans">
      {/* Main Two-Column Hero Section (Full Height Centered) */}
      <main className="flex-1 flex items-center relative z-10 px-6 sm:px-10 lg:px-16 py-6 lg:py-0 max-w-7xl mx-auto w-full">
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-8 lg:gap-12 items-center w-full my-auto">
          
          {/* LEFT SIDE: Clean Branding, Headline, Description, CTA */}
          <div className="lg:col-span-6 flex flex-col justify-center text-left space-y-6 z-20">
            
            {/* Clean Large Text Branding (CYBER in white, FORECASTER in gold) */}
            <div>
              <span className="text-2xl sm:text-3xl lg:text-4xl font-black tracking-widest font-mono-tech uppercase">
                <span className="text-white">CYBER</span>
                <span className="text-gold">FORECASTER</span>
              </span>
            </div>

            {/* Main Headline / Tagline */}
            <h1 className="text-4xl sm:text-5xl lg:text-6xl font-black tracking-tight leading-[1.1] text-white">
              See the Attack{" "}
              <span className="text-gold">
                Before It Happens
              </span>
            </h1>

            {/* Supporting Text */}
            <p className="text-base sm:text-lg text-text-muted leading-relaxed font-normal max-w-xl">
              Stay ahead of cyber threats with intelligent insights from your network.
            </p>

            {/* Call To Action Button */}
            <div className="pt-2">
              <button
                id="get-started-btn"
                onClick={onGetStarted}
                className="group relative inline-flex items-center justify-center gap-3 px-8 py-4 rounded-lg text-base sm:text-lg font-mono-tech font-bold uppercase tracking-wider text-bg bg-gold border border-gold hover:bg-gold-hi transition-all duration-300 ease-out cursor-pointer"
              >
                <span>GET STARTED</span>
                <ArrowRight className="h-5 w-5 text-bg group-hover:translate-x-1 transition-transform duration-300" />
              </button>
            </div>

            {/* Subtle Tech Indicators */}
            <div className="pt-4 border-t border-border grid grid-cols-2 gap-4 max-w-md text-sm font-mono-tech text-text-muted">
              <div className="flex items-center gap-2">
                <Cpu className="h-4 w-4 text-gold" />
                <span>PyTorch LSTM Forecasting</span>
              </div>
              <div className="flex items-center gap-2">
                <Lock className="h-4 w-4 text-gold" />
                <span>Evidence-Supported Assessment</span>
              </div>
            </div>

          </div>

          {/* RIGHT SIDE: Spline 3D Robot */}
          <div className="lg:col-span-6 w-full h-[400px] sm:h-[480px] lg:h-[580px] relative flex items-center justify-center">
            {/* Robot Direct Container */}
            <div className="w-full h-full relative flex items-center justify-center">
              
              {/* Loading skeleton / Fallback */}
              {!isSceneLoaded && (
                <div className="absolute inset-0 flex flex-col items-center justify-center text-center p-4">
                  <div className="h-10 w-10 border-2 border-border border-t-gold rounded-full animate-spin mb-3" />
                  <p className="text-sm font-mono-tech text-gold font-bold tracking-wider">
                    INITIALIZING 3D ROBOT...
                  </p>
                </div>
              )}

              {/* Spline 3D Scene */}
              <Suspense
                fallback={
                  <div className="w-full h-full flex items-center justify-center">
                    <div className="h-8 w-8 border-2 border-border border-t-gold rounded-full animate-spin" />
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
    </div>
  );
}

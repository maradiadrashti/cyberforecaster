import React, { useEffect, useRef, useState, useCallback } from "react";
import { Gamepad2, RotateCcw, Trophy, Zap, Volume2, VolumeX } from "lucide-react";

export default function DinoGame() {
  const canvasRef = useRef(null);
  const [gameState, setGameState] = useState("START"); // START, PLAYING, GAMEOVER
  const [score, setScore] = useState(0);
  const [highScore, setHighScore] = useState(() => {
    return parseInt(localStorage.getItem("cyber_dino_highscore") || "0", 10);
  });
  const [muted, setMuted] = useState(false);

  // References for mutable game loop variables to prevent stale closures
  const stateRef = useRef({
    gameState: "START",
    score: 0,
    speed: 6,
    gravity: 0.6,
    dino: {
      x: 50,
      y: 190,
      w: 40,
      h: 45,
      vy: 0,
      isJumping: false,
      isDucking: false,
      groundY: 190,
    },
    obstacles: [],
    clouds: [],
    particles: [],
    spawnTimer: 0,
    cloudTimer: 0,
    frameCount: 0,
  });

  const jump = useCallback(() => {
    const s = stateRef.current;
    if (s.gameState === "START" || s.gameState === "GAMEOVER") {
      startGame();
      return;
    }
    if (s.gameState === "PLAYING" && !s.dino.isJumping) {
      s.dino.vy = -12;
      s.dino.isJumping = true;
    }
  }, []);

  const duck = useCallback((isDucking) => {
    const s = stateRef.current;
    if (s.gameState === "PLAYING") {
      s.dino.isDucking = isDucking;
      if (isDucking && !s.dino.isJumping) {
        s.dino.h = 25;
        s.dino.y = s.dino.groundY + 20;
      } else if (!isDucking) {
        s.dino.h = 45;
        if (!s.dino.isJumping) {
          s.dino.y = s.dino.groundY;
        }
      }
    }
  }, []);

  const startGame = () => {
    const s = stateRef.current;
    s.gameState = "PLAYING";
    s.score = 0;
    s.speed = 6;
    s.dino.y = s.dino.groundY;
    s.dino.vy = 0;
    s.dino.isJumping = false;
    s.dino.isDucking = false;
    s.dino.h = 45;
    s.obstacles = [];
    s.clouds = [];
    s.particles = [];
    s.spawnTimer = 0;
    s.frameCount = 0;
    setGameState("PLAYING");
    setScore(0);
  };

  // Keyboard Event Listeners
  useEffect(() => {
    const handleKeyDown = (e) => {
      if (e.code === "Space" || e.code === "ArrowUp") {
        e.preventDefault();
        jump();
      } else if (e.code === "ArrowDown") {
        e.preventDefault();
        duck(true);
      }
    };

    const handleKeyUp = (e) => {
      if (e.code === "ArrowDown") {
        duck(false);
      }
    };

    window.addEventListener("keydown", handleKeyDown);
    window.addEventListener("keyup", handleKeyUp);
    return () => {
      window.removeEventListener("keydown", handleKeyDown);
      window.removeEventListener("keyup", handleKeyUp);
    };
  }, [jump, duck]);

  // Main Canvas Render & Physics Loop
  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext("2d");
    let animId;

    const createParticles = (x, y, color) => {
      for (let i = 0; i < 15; i++) {
        stateRef.current.particles.push({
          x,
          y,
          vx: (Math.random() - 0.5) * 8,
          vy: (Math.random() - 0.5) * 8,
          life: 1,
          size: Math.random() * 4 + 2,
          color,
        });
      }
    };

    const render = () => {
      const s = stateRef.current;
      const width = canvas.width;
      const height = canvas.height;
      const groundLine = 235;

      ctx.clearRect(0, 0, width, height);

      // Background Gradient Grid
      const bgGrad = ctx.createLinearGradient(0, 0, 0, height);
      bgGrad.addColorStop(0, "#0B0F14");
      bgGrad.addColorStop(1, "#141A22");
      ctx.fillStyle = bgGrad;
      ctx.fillRect(0, 0, width, height);

      // Draw Horizon Ground Line
      ctx.strokeStyle = "#CBA135";
      ctx.lineWidth = 2;
      ctx.beginPath();
      ctx.moveTo(0, groundLine);
      ctx.lineTo(width, groundLine);
      ctx.stroke();

      // Moving Ground Grid Dots
      if (s.gameState === "PLAYING") {
        s.frameCount++;
        s.score += 0.15;
        const currentScore = Math.floor(s.score);
        setScore(currentScore);

        if (currentScore > highScore) {
          setHighScore(currentScore);
          localStorage.setItem("cyber_dino_highscore", currentScore.toString());
        }

        // Gradually increase speed
        if (s.frameCount % 300 === 0 && s.speed < 14) {
          s.speed += 0.5;
        }
      }

      // Draw Moving Ground Pattern Lines
      ctx.strokeStyle = "#262E3A";
      ctx.lineWidth = 1;
      const offset = (s.frameCount * s.speed) % 30;
      for (let x = -offset; x < width; x += 30) {
        ctx.beginPath();
        ctx.moveTo(x, groundLine);
        ctx.lineTo(x - 20, height);
        ctx.stroke();
      }

      // Draw & Update Clouds
      if (s.gameState === "PLAYING") {
        s.cloudTimer++;
        if (s.cloudTimer > 120) {
          s.clouds.push({
            x: width,
            y: Math.random() * 80 + 20,
            w: Math.random() * 40 + 30,
            speed: Math.random() * 1 + 1,
          });
          s.cloudTimer = 0;
        }
      }

      for (let i = s.clouds.length - 1; i >= 0; i--) {
        const c = s.clouds[i];
        if (s.gameState === "PLAYING") c.x -= c.speed;
        ctx.fillStyle = "rgba(62, 99, 199, 0.2)";
        ctx.beginPath();
        ctx.arc(c.x, c.y, c.w / 3, 0, Math.PI * 2);
        ctx.arc(c.x + 15, c.y - 5, c.w / 3, 0, Math.PI * 2);
        ctx.arc(c.x + 30, c.y, c.w / 3, 0, Math.PI * 2);
        ctx.fill();

        if (c.x + c.w < 0) s.clouds.splice(i, 1);
      }

      // Update Dino Physics
      const d = s.dino;
      if (s.gameState === "PLAYING") {
        if (d.isJumping) {
          d.vy += s.gravity;
          d.y += d.vy;

          if (d.y >= d.groundY) {
            d.y = d.groundY;
            d.vy = 0;
            d.isJumping = false;
          }
        }
      }

      // Draw Dino
      const dinoX = d.x;
      const dinoY = d.y;

      ctx.fillStyle = "#CBA135";

      if (!d.isDucking) {
        // --- STANDING / RUNNING DINO ---
        ctx.fillRect(dinoX + 18, dinoY, 24, 14); // Upper Head & Snout
        ctx.fillRect(dinoX + 18, dinoY + 14, 16, 4); // Lower Jaw

        // Eye
        ctx.fillStyle = "#0B0F14";
        ctx.fillRect(dinoX + 22, dinoY + 3, 4, 4);
        ctx.fillStyle = "#FFFFFF";
        ctx.fillRect(dinoX + 23, dinoY + 4, 2, 2);

        // Mouth Opening
        ctx.fillStyle = "#0B0F14";
        ctx.fillRect(dinoX + 24, dinoY + 12, 18, 2);

        // Body Color
        ctx.fillStyle = "#CBA135";

        ctx.fillRect(dinoX + 18, dinoY + 14, 10, 8);
        ctx.fillRect(dinoX + 8, dinoY + 18, 20, 18);
        ctx.fillRect(dinoX + 4, dinoY + 16, 6, 8);
        ctx.fillRect(dinoX, dinoY + 14, 6, 6);
        ctx.fillRect(dinoX - 4, dinoY + 12, 6, 4);
        ctx.fillRect(dinoX + 28, dinoY + 22, 6, 3);
        ctx.fillRect(dinoX + 32, dinoY + 24, 2, 3);

        if (s.gameState === "PLAYING" && !d.isJumping) {
          const legStep = Math.floor(s.frameCount / 5) % 2;
          if (legStep === 0) {
            ctx.fillRect(dinoX + 10, dinoY + 36, 5, 11);
            ctx.fillRect(dinoX + 10, dinoY + 45, 8, 3);
            ctx.fillRect(dinoX + 20, dinoY + 36, 5, 5);
            ctx.fillRect(dinoX + 23, dinoY + 40, 5, 3);
          } else {
            ctx.fillRect(dinoX + 10, dinoY + 36, 5, 5);
            ctx.fillRect(dinoX + 7, dinoY + 40, 5, 3);
            ctx.fillRect(dinoX + 20, dinoY + 36, 5, 11);
            ctx.fillRect(dinoX + 20, dinoY + 45, 8, 3);
          }
        } else {
          ctx.fillRect(dinoX + 10, dinoY + 36, 5, 10);
          ctx.fillRect(dinoX + 10, dinoY + 44, 7, 3);
          ctx.fillRect(dinoX + 20, dinoY + 36, 5, 10);
          ctx.fillRect(dinoX + 20, dinoY + 44, 7, 3);
        }
      } else {
        // --- DUCKING DINO ---
        ctx.fillRect(dinoX + 28, dinoY + 2, 26, 12);
        ctx.fillRect(dinoX + 28, dinoY + 14, 18, 4);

        ctx.fillStyle = "#0B0F14";
        ctx.fillRect(dinoX + 32, dinoY + 4, 4, 4);
        ctx.fillStyle = "#FFFFFF";
        ctx.fillRect(dinoX + 33, dinoY + 5, 2, 2);

        ctx.fillStyle = "#0B0F14";
        ctx.fillRect(dinoX + 34, dinoY + 12, 18, 2);

        ctx.fillStyle = "#CBA135";

        ctx.fillRect(dinoX + 8, dinoY + 8, 24, 14);
        ctx.fillRect(dinoX + 2, dinoY + 6, 8, 6);
        ctx.fillRect(dinoX - 4, dinoY + 4, 6, 4);
        ctx.fillRect(dinoX + 36, dinoY + 16, 6, 3);

        if (s.gameState === "PLAYING") {
          const legStep = Math.floor(s.frameCount / 5) % 2;
          if (legStep === 0) {
            ctx.fillRect(dinoX + 12, dinoY + 22, 5, 8);
            ctx.fillRect(dinoX + 12, dinoY + 28, 7, 2);
            ctx.fillRect(dinoX + 22, dinoY + 22, 5, 5);
          } else {
            ctx.fillRect(dinoX + 12, dinoY + 22, 5, 5);
            ctx.fillRect(dinoX + 22, dinoY + 22, 5, 8);
            ctx.fillRect(dinoX + 22, dinoY + 28, 7, 2);
          }
        } else {
          ctx.fillRect(dinoX + 12, dinoY + 22, 5, 8);
          ctx.fillRect(dinoX + 22, dinoY + 22, 5, 8);
        }
      }

      // Spawn & Draw Obstacles (Cacti / Flying Drones)
      if (s.gameState === "PLAYING") {
        s.spawnTimer++;
        const minSpawn = Math.max(50, 100 - Math.floor(s.score / 50));
        if (s.spawnTimer > minSpawn + Math.random() * 40) {
          const type = Math.random() > 0.3 ? "CACTUS" : "DRONE";
          if (type === "CACTUS") {
            const isDouble = Math.random() > 0.6;
            s.obstacles.push({
              type: "CACTUS",
              x: width,
              y: groundLine - (isDouble ? 45 : 35),
              w: isDouble ? 35 : 20,
              h: isDouble ? 45 : 35,
              color: "#3E63C7",
            });
          } else {
            const flyY = Math.random() > 0.5 ? groundLine - 65 : groundLine - 35;
            s.obstacles.push({
              type: "DRONE",
              x: width,
              y: flyY,
              w: 30,
              h: 20,
              color: "#CBA135",
            });
          }
          s.spawnTimer = 0;
        }
      }

      // Update & Draw Obstacles
      for (let i = s.obstacles.length - 1; i >= 0; i--) {
        const obs = s.obstacles[i];
        if (s.gameState === "PLAYING") obs.x -= s.speed;

        ctx.fillStyle = obs.color;

        if (obs.type === "CACTUS") {
          ctx.fillRect(obs.x, obs.y, obs.w, obs.h);
          ctx.fillStyle = "#FFFFFF";
          ctx.fillRect(obs.x + 2, obs.y + 4, obs.w - 4, 3);
        } else {
          ctx.fillRect(obs.x, obs.y, obs.w, obs.h);
          const wingUp = Math.floor(s.frameCount / 8) % 2 === 0;
          ctx.fillStyle = "#E0C36A";
          ctx.fillRect(obs.x + 5, wingUp ? obs.y - 8 : obs.y + obs.h, 20, 5);
        }

        // Collision Detection
        if (s.gameState === "PLAYING") {
          const dinoBox = { x: d.x + 4, y: d.y + 2, w: d.w - 8, h: d.h - 4 };
          const obsBox = { x: obs.x + 2, y: obs.y + 2, w: obs.w - 4, h: obs.h - 4 };

          if (
            dinoBox.x < obsBox.x + obsBox.w &&
            dinoBox.x + dinoBox.w > obsBox.x &&
            dinoBox.y < obsBox.y + obsBox.h &&
            dinoBox.y + dinoBox.h > obsBox.y
          ) {
            s.gameState = "GAMEOVER";
            setGameState("GAMEOVER");
            createParticles(d.x + d.w / 2, d.y + d.h / 2, "#CBA135");
          }
        }

        if (obs.x + obs.w < 0) s.obstacles.splice(i, 1);
      }

      // Draw Particle Explosions
      for (let i = s.particles.length - 1; i >= 0; i--) {
        const p = s.particles[i];
        p.x += p.vx;
        p.y += p.vy;
        p.life -= 0.03;

        ctx.fillStyle = p.color;
        ctx.globalAlpha = Math.max(0, p.life);
        ctx.fillRect(p.x, p.y, p.size, p.size);
        ctx.globalAlpha = 1.0;

        if (p.life <= 0) s.particles.splice(i, 1);
      }

      animId = requestAnimationFrame(render);
    };

    render();

    return () => {
      cancelAnimationFrame(animId);
    };
  }, [highScore]);

  return (
    <div className="flex flex-col items-center justify-center w-full max-w-5xl mx-auto select-none">
      {/* Expanded Canvas Viewport */}
      <div className="relative w-full aspect-[16/7] min-h-[380px] sm:min-h-[420px] bg-surface rounded-2xl border border-border overflow-hidden group shadow-2xl">
        {/* Floating In-Game HUD (Score & HI) */}
        <div className="absolute top-4 right-4 flex items-center gap-3 z-10 pointer-events-auto font-mono-tech">
          <div className="flex items-center gap-2 text-white text-xs font-bold bg-surface-2/90 backdrop-blur-md border border-border px-3 py-1.5 rounded-xl shadow">
            <Trophy className="h-3.5 w-3.5 text-gold" />
            <span>HI: {highScore.toString().padStart(5, "0")}</span>
          </div>
          <div className="flex items-center gap-2 text-bg text-xs font-bold bg-gold border border-gold px-3.5 py-1.5 rounded-xl justify-center shadow">
            <Zap className="h-3.5 w-3.5 text-bg" />
            <span>{score.toString().padStart(5, "0")}</span>
          </div>
          <button
            onClick={() => setMuted(!muted)}
            className="p-1.5 rounded-xl bg-surface-2/90 backdrop-blur-md border border-border text-text-muted hover:text-white transition-colors cursor-pointer"
            title="Toggle Mute"
          >
            {muted ? <VolumeX className="h-4 w-4" /> : <Volume2 className="h-4 w-4" />}
          </button>
        </div>

        <canvas
          ref={canvasRef}
          width={800}
          height={300}
          onClick={jump}
          className="w-full h-full cursor-pointer block"
        />

        {/* Start Overlay */}
        {gameState === "START" && (
          <div
            onClick={startGame}
            className="absolute inset-0 bg-bg/90 backdrop-blur-sm flex flex-col items-center justify-center p-6 space-y-4 cursor-pointer z-20"
          >
            <div className="p-4 rounded-full bg-gold text-bg animate-bounce">
              <Gamepad2 className="h-10 w-10" />
            </div>
            <div className="text-center space-y-1">
              <h3 className="text-xl font-bold font-mono-tech text-white uppercase tracking-wider">
                PRESS SPACE OR CLICK TO RUN
              </h3>
              <p className="text-sm font-mono-tech text-text-muted">
                [SPACE / UP] Jump &nbsp;|&nbsp; [DOWN] Duck &nbsp;|&nbsp; Dodge hazards
              </p>
            </div>
          </div>
        )}

        {/* Game Over Overlay */}
        {gameState === "GAMEOVER" && (
          <div
            onClick={startGame}
            className="absolute inset-0 bg-bg/95 backdrop-blur-md flex flex-col items-center justify-center p-6 space-y-4 cursor-pointer animate-fade-in z-20"
          >
            <div className="text-center space-y-2">
              <h3 className="text-2xl font-extrabold font-mono-tech text-gold uppercase tracking-widest">
                SYSTEM COLLISION — GAME OVER
              </h3>
              <p className="text-sm font-mono-tech text-text">
                Final Score: <span className="text-gold font-bold">{score}</span>
              </p>
            </div>

            <button
              onClick={startGame}
              className="flex items-center gap-2 px-6 py-2.5 rounded-xl bg-gold text-bg font-mono-tech font-bold text-sm uppercase tracking-wider hover:bg-gold-hi transition-all cursor-pointer"
            >
              <RotateCcw className="h-4 w-4" />
              <span>RETRY TRANSMISSION</span>
            </button>
          </div>
        )}
      </div>
    </div>
  );
}

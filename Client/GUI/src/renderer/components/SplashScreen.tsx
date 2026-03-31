import { motion, AnimatePresence } from "framer-motion";
import { Shield, Lock, Zap } from "lucide-react";
import logo from "../assets/logo.png";
import { APP_VERSION } from "@shared/antivirus";

interface SplashScreenProps {
  isVisible: boolean;
  status?: string;
}

const SplashScreen = ({
  isVisible,
  status = "Initializing Core Engine",
}: SplashScreenProps) => {
  return (
    <AnimatePresence>
      {isVisible && (
        <motion.div
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          exit={{
            opacity: 0,
            transition: { duration: 0.8, ease: [0.43, 0.13, 0.23, 0.96] },
          }}
          className="fixed inset-0 z-[9999] flex items-center justify-center bg-[#05070a] overflow-hidden"
        >
          {/* Dynamic background effects */}
          <div className="absolute inset-0 overflow-hidden pointer-events-none">
            <motion.div
              animate={{
                scale: [1, 1.1, 1],
                opacity: [0.15, 0.25, 0.15],
              }}
              transition={{ duration: 8, repeat: Infinity, ease: "easeInOut" }}
              className="absolute -inset-[10%] bg-[radial-gradient(circle_at_50%_50%,rgba(56,104,255,0.2),transparent_70%)]"
            />

            {/* Animated Grid */}
            <div
              className="absolute inset-0 opacity-[0.03]"
              style={{
                backgroundImage: `linear-gradient(rgba(255,255,255,0.1) 1px, transparent 1px), linear-gradient(90deg, rgba(255,255,255,0.1) 1px, transparent 1px)`,
                backgroundSize: "50px 50px",
              }}
            />

            {/* Moving light streaks */}
            <motion.div
              animate={{
                x: ["-100%", "200%"],
                y: ["-100%", "200%"],
              }}
              transition={{ duration: 10, repeat: Infinity, ease: "linear" }}
              className="absolute top-0 left-0 w-1/2 h-1 bg-gradient-to-r from-transparent via-accent/20 to-transparent -rotate-45 blur-sm"
            />
          </div>

          <div className="relative flex flex-col items-center">
            {/* Logo container with pulse and glow */}
            <motion.div
              initial={{ scale: 0.9, opacity: 0, rotateY: -20 }}
              animate={{
                scale: 1,
                opacity: 1,
                rotateY: 0,
                transition: { duration: 1.5, ease: [0.16, 1, 0.3, 1] },
              }}
              whileHover={{ scale: 1.05 }}
              className="relative mb-16 perspective-1000"
            >
              <div className="absolute inset-0 blur-[100px] bg-accent/40 rounded-full animate-pulse" />
              <div className="relative z-10 p-10 rounded-[2.5rem] bg-white/[0.03] border border-white/10 backdrop-blur-2xl shadow-[0_25px_80px_rgba(0,0,0,0.5)] transition-all duration-500 hover:border-accent/40">
                <img
                  src={logo}
                  alt="Aydo Logo"
                  className="h-28 w-auto filter drop-shadow-[0_0_15px_rgba(255,255,255,0.1)]"
                />
              </div>

              {/* Peripheral icons spinning/orbiting */}
              <motion.div
                animate={{ rotate: 360 }}
                transition={{ duration: 25, repeat: Infinity, ease: "linear" }}
                className="absolute inset-0 -m-12 pointer-events-none"
              >
                <Shield
                  className="absolute top-0 left-1/2 -translate-x-1/2 -translate-y-full text-accent/30"
                  size={28}
                />
                <Lock
                  className="absolute bottom-0 left-1/2 -translate-x-1/2 translate-y-full text-accent/30"
                  size={28}
                />
                <Zap
                  className="absolute left-0 top-1/2 -translate-x-full -translate-y-1/2 text-accent/30"
                  size={28}
                />
              </motion.div>
            </motion.div>

            {/* Title and loading text */}
            <motion.div
              initial={{ y: 20, opacity: 0 }}
              animate={{ y: 0, opacity: 1, transition: { delay: 0.6 } }}
              className="text-center"
            >
              <h1 className="text-5xl font-black tracking-[0.15em] text-white mb-4 font-display">
                AYDO <span className="text-accent">AV</span>
              </h1>

              <div className="flex flex-col items-center gap-4">
                <p className="text-slate-400 text-xs font-bold tracking-[0.3em] uppercase opacity-80 h-4">
                  {status}
                </p>

                <div className="flex gap-2">
                  {[0, 1, 2].map((i) => (
                    <motion.div
                      key={i}
                      animate={{
                        scale: [1, 1.5, 1],
                        opacity: [0.3, 1, 0.3],
                        backgroundColor: "#3868FF",
                      }}
                      transition={{
                        duration: 1.2,
                        repeat: Infinity,
                        delay: i * 0.2,
                      }}
                      className="h-2 w-2 rounded-full bg-accent shadow-[0_0_8px_rgba(56,104,255,0.5)]"
                    />
                  ))}
                </div>
              </div>
            </motion.div>

            {/* Progress bar */}
            <motion.div
              initial={{ width: 0, opacity: 0 }}
              animate={{ width: 300, opacity: 1, transition: { delay: 1 } }}
              className="h-[3px] bg-white/5 rounded-full mt-12 overflow-hidden relative"
            >
              <motion.div
                className="absolute inset-y-0 left-0 bg-accent shadow-[0_0_20px_rgba(56,104,255,0.8)]"
                animate={{
                  left: ["-100%", "100%"],
                }}
                transition={{
                  duration: 2.5,
                  repeat: Infinity,
                  ease: "easeInOut",
                }}
                style={{ width: "40%" }}
              />
            </motion.div>

            {/* Author Credits */}
            <motion.div
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: 2, duration: 1, ease: "easeOut" }}
              className="mt-16 flex flex-col items-center"
            >
              <motion.div
                initial={{ width: 0 }}
                animate={{ width: 40 }}
                transition={{ delay: 2.5, duration: 1 }}
                className="h-[1px] bg-gradient-to-r from-transparent via-accent/50 to-transparent mb-6"
              />
              <p className="text-[10px] text-slate-500 font-bold tracking-[0.6em] uppercase mb-3 opacity-50">
                Architected By
              </p>
              <h2 className="text-2xl font-display tracking-tight text-white/40 flex items-baseline gap-1.5">
                by
                <span className="text-white/80">
                  It
                  <span className="text-accent font-black drop-shadow-[0_0_10px_rgba(56,104,255,0.4)]">
                    ay
                  </span>
                </span>
                <span className="text-slate-600 font-light mx-1">&</span>
                <span className="text-white/80">
                  <span className="text-accent font-black drop-shadow-[0_0_10px_rgba(56,104,255,0.4)]">
                    Do
                  </span>
                  rian
                </span>
              </h2>
            </motion.div>
          </div>

          {/* Footer note */}
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1, transition: { delay: 1.5 } }}
            className="absolute bottom-12 text-slate-600 text-[11px] font-bold uppercase tracking-[0.4em]"
          >
            THE MOST SIGMA AV · v{APP_VERSION}
          </motion.div>
        </motion.div>
      )}
    </AnimatePresence>
  );
};

export default SplashScreen;

import { Moon, Sun } from "lucide-react";
import { useTheme } from "next-themes";

const ThemeToggle = ({ className = "" }: { className?: string }) => {
  const { resolvedTheme, setTheme } = useTheme();

  const toggle = () => {
    setTheme(resolvedTheme === "dark" ? "light" : "dark");
  };

  return (
    <button
      onClick={toggle}
      className={`flex h-10 w-10 items-center justify-center rounded-full border border-white/10 bg-white/5 text-slate-700 transition hover:text-slate-900 dark:text-white/70 dark:hover:text-white ${className}`}
      aria-label="Toggle theme"
      type="button"
    >
      {resolvedTheme === "dark" ? <Sun size={16} /> : <Moon size={16} />}
    </button>
  );
};

export default ThemeToggle;

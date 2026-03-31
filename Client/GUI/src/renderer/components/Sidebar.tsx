import { Sliders, Activity, Newspaper, LogOut } from "lucide-react";
import { NavLink, useNavigate } from "react-router-dom";
import { authService } from "../services/authService";
import logoUrl from "../../../assets/brand/icon.png";
import BrandMark from "./BrandMark";

const navItems = [
  { to: "/dashboard", icon: Activity, label: "Dashboard" },
  { to: "/news", icon: Newspaper, label: "News" },
  { to: "/settings", icon: Sliders, label: "Settings" },
] as const;

const linkBase =
  "group flex items-center gap-3 rounded-xl px-4 py-3 text-sm font-medium transition-all duration-200";

const Sidebar = () => {
  const navigate = useNavigate();

  const handleLogout = () => {
    authService.logout();
    navigate("/login");
  };

  return (
    <aside className="relative flex flex-col h-full w-64 border-r border-slate-200/70 bg-slate-50/90 px-5 py-8 backdrop-blur-xl dark:border-white/10 dark:bg-slate-950/40 pt-20">
      {/* Logo */}
      <div className="flex flex-col items-center gap-3 px-1">
        <BrandMark className="h-9 w-9" />
        <span className="text-[9px] uppercase tracking-[0.35em] text-muted">
          Security Console
        </span>
      </div>

      {/* Navigation */}
      <nav className="flex flex-col gap-1.5">
        {navItems.map(({ to, icon: Icon, label }) => (
          <NavLink
            key={to}
            to={to}
            className={({ isActive }) =>
              `${linkBase} ${
                isActive
                  ? "bg-accent/15 text-accent shadow-[0_0_0_1px_rgba(90,130,255,0.25),0_4px_12px_rgba(0,0,0,0.15)]"
                  : "text-slate-700 hover:bg-slate-200/40 dark:text-white/70 dark:hover:bg-white/5 dark:hover:text-white"
              }`
            }
          >
            <Icon size={18} className="shrink-0" />
            {label}
          </NavLink>
        ))}
      </nav>

      {/* Spacer to push content above bottom button */}
      <div className="flex-1" />

      {/* Bottom sign-out */}
      <div className="absolute bottom-0 left-0 right-0 border-t border-slate-200/70 bg-slate-50/90 px-5 py-4 backdrop-blur-xl dark:border-white/10 dark:bg-slate-950/40">
        <button
          onClick={handleLogout}
          className="flex w-full items-center gap-3 rounded-xl px-4 py-3 text-sm font-medium text-slate-600 transition-all duration-200 hover:bg-danger/10 hover:text-danger dark:text-white/60 dark:hover:bg-danger/10 dark:hover:text-danger"
        >
          <LogOut size={18} className="shrink-0" />
          Sign out
        </button>
      </div>
    </aside>
  );
};

export default Sidebar;

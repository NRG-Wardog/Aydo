import { ReactNode } from "react";
import Sidebar from "./Sidebar";
import Topbar from "./Topbar";
import TitleBar from "./TitleBar";

const Shell = ({
  title,
  subtitle,
  children,
}: {
  title: string;
  subtitle?: string;
  children: ReactNode;
}) => {
  return (
    <div className="flex min-h-screen">
      <div className="fixed left-0 top-0 h-screen w-64 z-30">
        <Sidebar />
      </div>
      <div className="flex flex-1 flex-col min-h-screen ml-64">
        <TitleBar />
        <div className="pt-12 flex-1">
          <Topbar title={title} subtitle={subtitle} />
          <main className="flex-1 px-8 py-8">
            <div className="mx-auto flex w-full max-w-6xl flex-col gap-6">
              {children}
            </div>
          </main>
        </div>
      </div>
    </div>
  );
};

export default Shell;

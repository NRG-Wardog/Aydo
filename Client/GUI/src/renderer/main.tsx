import React from "react";
import ReactDOM from "react-dom/client";
import { NextUIProvider } from "@nextui-org/react";
import { ThemeProvider } from "next-themes";
import { HashRouter } from "react-router-dom";
import App from "./App";
import "./styles/globals.css";

ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <ThemeProvider attribute="class" defaultTheme="dark" enableSystem={false}>
      <NextUIProvider>
        <HashRouter>
          <App />
        </HashRouter>
      </NextUIProvider>
    </ThemeProvider>
  </React.StrictMode>
);

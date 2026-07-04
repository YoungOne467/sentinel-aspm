import React, { createContext, useContext, useEffect, useState } from "react";

interface PerformanceContextType {
  isPerformanceMode: boolean;
  togglePerformanceMode: () => void;
}

const PerformanceContext = createContext<PerformanceContextType | undefined>(
  undefined
);

export const PerformanceProvider: React.FC<{ children: React.ReactNode }> = ({
  children,
}) => {
  const [isPerformanceMode, setIsPerformanceMode] = useState<boolean>(() => {
    if (typeof window === "undefined") return false;
    const stored = localStorage.getItem("aspm_performance_mode");
    if (stored !== null) {
      return stored === "true";
    }
    return window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  });

  useEffect(() => {
    localStorage.setItem("aspm_performance_mode", String(isPerformanceMode));
  }, [isPerformanceMode]);

  const togglePerformanceMode = () => {
    setIsPerformanceMode((prev) => !prev);
  };

  return (
    <PerformanceContext.Provider
      value={{ isPerformanceMode, togglePerformanceMode }}
    >
      {children}
    </PerformanceContext.Provider>
  );
};

export const usePerformanceMode = () => {
  const context = useContext(PerformanceContext);
  if (context === undefined) {
    throw new Error(
      "usePerformanceMode must be used within a PerformanceProvider"
    );
  }
  return context;
};

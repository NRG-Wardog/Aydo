import { useEffect, useState } from "react";
import { useMotionValue, useSpring } from "framer-motion";

const AnimatedNumber = ({ value, suffix = "" }: { value: number; suffix?: string }) => {
  const motionValue = useMotionValue(value);
  const spring = useSpring(motionValue, { stiffness: 120, damping: 18 });
  const [display, setDisplay] = useState(value);

  useEffect(() => {
    motionValue.set(value);
  }, [motionValue, value]);

  useEffect(() => {
    const unsubscribe = spring.on("change", (latest) => {
      setDisplay(Math.round(latest));
    });
    return () => unsubscribe();
  }, [spring]);

  return (
    <span className="font-display text-3xl font-semibold tracking-tight">
      {display.toLocaleString()}
      {suffix}
    </span>
  );
};

export default AnimatedNumber;

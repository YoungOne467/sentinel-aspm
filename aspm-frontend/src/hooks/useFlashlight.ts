import { useEffect, useState } from 'react';
import { useSecurityStore } from '../store';

export function useFlashlight(ref: React.RefObject<HTMLElement | null>) {
  const isEcoMode = useSecurityStore((state) => state.isEcoMode);
  const [position, setPosition] = useState({ x: 0, y: 0 });

  useEffect(() => {
    if (isEcoMode || !ref.current) return;

    const element = ref.current;

    const updatePosition = (e: MouseEvent) => {
      const rect = element.getBoundingClientRect();
      const x = e.clientX - rect.left;
      const y = e.clientY - rect.top;
      setPosition({ x, y });
    };

    element.addEventListener('mousemove', updatePosition);
    return () => element.removeEventListener('mousemove', updatePosition);
  }, [isEcoMode, ref]);

  return position;
}

import React, { useEffect, useRef } from 'react';

interface VantaBackgroundProps {
  color?: number;
  backgroundColor?: number;
  points?: number;
  maxDistance?: number;
}

export const VantaBackground: React.FC<VantaBackgroundProps> = ({
  color = 0x3b82f6,           // Electric Blue nodes
  backgroundColor = 0x0a0e1a, // Space Void Navy base
  points = 14.0,
  maxDistance = 22.0,
}) => {
  const vantaRef = useRef<HTMLDivElement>(null);
  const effectRef = useRef<any>(null);

  useEffect(() => {
    let isMounted = true;

    // Dynamic lazy import to avoid blocking main thread render
    Promise.all([import('three'), import('vanta/dist/vanta.net.min')])
      .then(([THREE, VANTA]) => {
        if (!isMounted || !vantaRef.current) return;

        effectRef.current = (VANTA as any).default({
          el: vantaRef.current,
          THREE,
          color,
          backgroundColor,
          points,
          maxDistance,
          spacing: 18.0,
          showDots: true,
        });
      })
      .catch((err) => {
        console.warn('Vanta.js WebGL background fallback to CSS gradient:', err);
      });

    return () => {
      isMounted = false;
      if (effectRef.current) {
        effectRef.current.destroy();
      }
    };
  }, [color, backgroundColor, points, maxDistance]);

  return (
    <div
      ref={vantaRef}
      className="fixed inset-0 -z-10 pointer-events-none transition-opacity duration-500 opacity-90"
      aria-hidden="true"
    />
  );
};

export default VantaBackground;

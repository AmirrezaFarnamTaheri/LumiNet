import React, { useEffect, useRef } from 'react';

export interface NodeMarker {
  id: string;
  lat: number;
  lon: number;
  latencyMs: number;
  label: string;
}

interface NodeGlobeProps {
  nodes?: NodeMarker[];
  width?: number;
  height?: number;
}

function getLatencyHexColor(ms: number): number {
  if (ms < 100) return 0x10b981;   // Terminal Green (<100ms)
  if (ms < 250) return 0xf59e0b;   // Warning Amber (100-250ms)
  return 0xef4444;                 // Alert Red (>250ms)
}

function latLonToXYZ(lat: number, lon: number, radius: number = 1.0): [number, number, number] {
  const phi = (90 - lat) * (Math.PI / 180);
  const theta = (lon + 180) * (Math.PI / 180);
  return [
    -(radius * Math.sin(phi) * Math.cos(theta)),
    radius * Math.cos(phi),
    radius * Math.sin(phi) * Math.sin(theta),
  ];
}

export const NodeGlobe: React.FC<NodeGlobeProps> = ({
  nodes = [],
  width = 400,
  height = 400,
}) => {
  const containerRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    let isMounted = true;
    let animationFrameId: number;

    import('three').then((THREE) => {
      if (!isMounted || !containerRef.current) return;

      const scene = new THREE.Scene();
      const camera = new THREE.PerspectiveCamera(45, width / height, 0.1, 1000);
      camera.position.z = 2.5;

      const renderer = new THREE.WebGLRenderer({ alpha: true, antialias: true });
      renderer.setSize(width, height);
      renderer.setPixelRatio(window.devicePixelRatio || 1);

      // Clean container
      containerRef.current.innerHTML = '';
      containerRef.current.appendChild(renderer.domElement);

      // Globe sphere mesh
      const geometry = new THREE.SphereGeometry(1.0, 32, 32);
      const material = new THREE.MeshStandardMaterial({
        color: 0x0f1425,
        wireframe: true,
        transparent: true,
        opacity: 0.4,
      });
      const globeMesh = new THREE.Mesh(geometry, material);
      scene.add(globeMesh);

      // Ambient & Directional Lighting
      const ambientLight = new THREE.AmbientLight(0xffffff, 0.8);
      scene.add(ambientLight);

      const dirLight = new THREE.DirectionalLight(0x3b82f6, 1.2);
      dirLight.position.set(5, 3, 5);
      scene.add(dirLight);

      // Render Node Markers
      nodes.forEach((node) => {
        const [x, y, z] = latLonToXYZ(node.lat, node.lon, 1.02);
        const markerGeo = new THREE.SphereGeometry(0.03, 16, 16);
        const markerMat = new THREE.MeshBasicMaterial({
          color: getLatencyHexColor(node.latencyMs),
        });
        const markerMesh = new THREE.Mesh(markerGeo, markerMat);
        markerMesh.position.set(x, y, z);
        scene.add(markerMesh);
      });

      // Smooth Rotation Loop
      const animate = () => {
        if (!isMounted) return;
        globeMesh.rotation.y += 0.002;
        renderer.render(scene, camera);
        animationFrameId = requestAnimationFrame(animate);
      };
      animate();
    });

    return () => {
      isMounted = false;
      if (animationFrameId) {
        cancelAnimationFrame(animationFrameId);
      }
    };
  }, [nodes, width, height]);

  return (
    <div className="relative flex items-center justify-center">
      <div ref={containerRef} style={{ width, height }} />
    </div>
  );
};

export default NodeGlobe;

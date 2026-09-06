import React, { useEffect, useRef, useState } from 'react';
import { Globe, ShieldAlert, Activity, Cpu, Layers, RefreshCw, ZoomIn, ZoomOut } from 'lucide-react';

interface GeoNode {
  id: string;
  name: string;
  lat: number;
  lng: number;
  latencyMs: number;
  status: 'active' | 'degraded' | 'blocked';
  interference?: string;
  antibody?: string;
}

interface UnderseaCable {
  from: string;
  to: string;
  name: string;
  capacityTbps: number;
}

const GLOBAL_NODES: GeoNode[] = [
  { id: 'fra', name: 'Frankfurt (FRA)', lat: 50.11, lng: 8.68, latencyMs: 28, status: 'active' },
  { id: 'lon', name: 'London (LON)', lat: 51.5, lng: -0.12, latencyMs: 34, status: 'active' },
  { id: 'nyc', name: 'New York (NYC)', lat: 40.71, lng: -74.0, latencyMs: 76, status: 'active' },
  { id: 'lax', name: 'Los Angeles (LAX)', lat: 34.05, lng: -118.24, latencyMs: 142, status: 'active' },
  { id: 'tyo', name: 'Tokyo (TYO)', lat: 35.68, lng: 139.65, latencyMs: 185, status: 'active' },
  { id: 'sin', name: 'Singapore (SIN)', lat: 1.35, lng: 103.82, latencyMs: 160, status: 'active' },
  { id: 'thr', name: 'Tehran Middlebox Node', lat: 35.69, lng: 51.39, latencyMs: 42, status: 'blocked', interference: 'Stateful DPI RST Injection & SNI Filter', antibody: 'SNI-Split-Offset-3 (Applied)' },
  { id: 'syd', name: 'Sydney (SYD)', lat: -33.87, lng: 151.21, latencyMs: 210, status: 'active' },
];

const CABLE_HOPS: UnderseaCable[] = [
  { from: 'nyc', to: 'lon', name: 'TAT-14 (Trans-Atlantic)', capacityTbps: 64 },
  { from: 'lon', to: 'fra', name: 'Circe Europe Interconnect', capacityTbps: 120 },
  { from: 'fra', to: 'sin', name: 'SEA-ME-WE 5 (Eurasia)', capacityTbps: 24 },
  { from: 'sin', to: 'tyo', name: 'Asia Submarine-cable Express', capacityTbps: 40 },
  { from: 'tyo', to: 'lax', name: 'FASTER Trans-Pacific Cable', capacityTbps: 60 },
  { from: 'lax', to: 'nyc', name: 'Trans-Continental Terrestrial Backbone', capacityTbps: 100 },
  { from: 'sin', to: 'syd', name: 'Australia-Singapore Cable (ASC)', capacityTbps: 40 },
  { from: 'fra', to: 'thr', name: 'EPEG Middle-East Gateway (Monitored)', capacityTbps: 3.2 },
];

export const NetworkCockpit: React.FC = () => {
  const canvasRef = useRef<HTMLCanvasElement | null>(null);
  const [selectedNode, setSelectedNode] = useState<GeoNode | null>(GLOBAL_NODES[6] ?? null);
  const [autoRotate, setAutoRotate] = useState(true);
  const [zoom, setZoom] = useState(1.0);
  const [rotation, setRotation] = useState({ yaw: 0.8, pitch: 0.3 });
  const isDraggingRef = useRef(false);
  const lastMouseRef = useRef({ x: 0, y: 0 });

  // 3D Cartesian coordinates projection from Lat/Lng
  const latLngTo3D = (lat: number, lng: number, radius: number) => {
    const phi = (90 - lat) * (Math.PI / 180);
    const theta = (lng + 180) * (Math.PI / 180);
    const x = -radius * Math.sin(phi) * Math.cos(theta);
    const z = radius * Math.sin(phi) * Math.sin(theta);
    const y = radius * Math.cos(phi);
    return { x, y, z };
  };

  // Rotation transformation
  const rotatePoint = (p: { x: number; y: number; z: number }, yaw: number, pitch: number) => {
    // Rotate around Y axis (yaw)
    const cosY = Math.cos(yaw);
    const sinY = Math.sin(yaw);
    const x1 = p.x * cosY + p.z * sinY;
    const z1 = -p.x * sinY + p.z * cosY;

    // Rotate around X axis (pitch)
    const cosP = Math.cos(pitch);
    const sinP = Math.sin(pitch);
    const y2 = p.y * cosP - z1 * sinP;
    const z2 = p.y * sinP + z1 * cosP;

    return { x: x1, y: y2, z: z2 };
  };

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    let animationId: number;
    let animPulse = 0;

    const render = () => {
      animPulse += 0.04;
      if (autoRotate && !isDraggingRef.current) {
        setRotation((prev) => ({ ...prev, yaw: prev.yaw + 0.003 }));
      }

      const width = canvas.width;
      const height = canvas.height;
      const centerX = width / 2;
      const centerY = height / 2;
      const baseRadius = Math.min(width, height) * 0.35 * zoom;

      ctx.clearRect(0, 0, width, height);

      // 1. Draw Globe Atmospheric Glow
      const glowGrad = ctx.createRadialGradient(centerX, centerY, baseRadius * 0.8, centerX, centerY, baseRadius * 1.25);
      glowGrad.addColorStop(0, 'rgba(59, 130, 246, 0.15)');
      glowGrad.addColorStop(0.5, 'rgba(37, 99, 235, 0.05)');
      glowGrad.addColorStop(1, 'rgba(0, 0, 0, 0)');
      ctx.fillStyle = glowGrad;
      ctx.beginPath();
      ctx.arc(centerX, centerY, baseRadius * 1.25, 0, Math.PI * 2);
      ctx.fill();

      // 2. Draw Sphere Surface
      const sphereGrad = ctx.createRadialGradient(
        centerX - baseRadius * 0.3,
        centerY - baseRadius * 0.3,
        baseRadius * 0.1,
        centerX,
        centerY,
        baseRadius
      );
      sphereGrad.addColorStop(0, '#0f172a');
      sphereGrad.addColorStop(0.8, '#020617');
      sphereGrad.addColorStop(1, '#1e293b');

      ctx.fillStyle = sphereGrad;
      ctx.beginPath();
      ctx.arc(centerX, centerY, baseRadius, 0, Math.PI * 2);
      ctx.fill();

      ctx.strokeStyle = 'rgba(56, 189, 248, 0.25)';
      ctx.lineWidth = 1.5;
      ctx.stroke();

      // 3. Draw 3D Latitude and Longitude Graticule lines
      ctx.strokeStyle = 'rgba(148, 163, 184, 0.12)';
      ctx.lineWidth = 1;

      for (let lat = -60; lat <= 60; lat += 30) {
        ctx.beginPath();
        let first = true;
        for (let lng = -180; lng <= 180; lng += 10) {
          const pt3 = latLngTo3D(lat, lng, baseRadius);
          const rpt = rotatePoint(pt3, rotation.yaw, rotation.pitch);
          if (rpt.z > -baseRadius * 0.1) {
            const sx = centerX + rpt.x;
            const sy = centerY - rpt.y;
            if (first) {
              ctx.moveTo(sx, sy);
              first = false;
            } else {
              ctx.lineTo(sx, sy);
            }
          } else {
            first = true;
          }
        }
        ctx.stroke();
      }

      // 4. Draw Undersea Cable 3D Arcs
      CABLE_HOPS.forEach((cable) => {
        const n1 = GLOBAL_NODES.find((n) => n.id === cable.from);
        const n2 = GLOBAL_NODES.find((n) => n.id === cable.to);
        if (!n1 || !n2) return;

        const p1_3d = latLngTo3D(n1.lat, n1.lng, baseRadius);
        const p2_3d = latLngTo3D(n2.lat, n2.lng, baseRadius);

        const r1 = rotatePoint(p1_3d, rotation.yaw, rotation.pitch);
        const r2 = rotatePoint(p2_3d, rotation.yaw, rotation.pitch);

        // Render only if at least partially visible on front hemisphere
        if (r1.z > -baseRadius * 0.2 || r2.z > -baseRadius * 0.2) {
          const x1 = centerX + r1.x;
          const y1 = centerY - r1.y;
          const x2 = centerX + r2.x;
          const y2 = centerY - r2.y;

          // Compute elevated 3D mid-point for arching cable
          const midLat = (n1.lat + n2.lat) / 2;
          const midLng = (n1.lng + n2.lng) / 2;
          const arcElevation = baseRadius * 1.18;
          const mid3d = latLngTo3D(midLat, midLng, arcElevation);
          const rMid = rotatePoint(mid3d, rotation.yaw, rotation.pitch);
          const midX = centerX + rMid.x;
          const midY = centerY - rMid.y;

          ctx.beginPath();
          ctx.moveTo(x1, y1);
          ctx.quadraticCurveTo(midX, midY, x2, y2);
          ctx.strokeStyle = cable.from === 'fra' && cable.to === 'thr'
            ? 'rgba(239, 68, 68, 0.65)'
            : 'rgba(56, 189, 248, 0.4)';
          ctx.lineWidth = cable.from === 'fra' && cable.to === 'thr' ? 2 : 1.5;
          ctx.stroke();

          // Animated traveling light packet
          const t = (animPulse * 0.5) % 1;
          const px = (1 - t) * (1 - t) * x1 + 2 * (1 - t) * t * midX + t * t * x2;
          const py = (1 - t) * (1 - t) * y1 + 2 * (1 - t) * t * midY + t * t * y2;

          ctx.fillStyle = cable.from === 'fra' && cable.to === 'thr' ? '#ef4444' : '#38bdf8';
          ctx.beginPath();
          ctx.arc(px, py, 2.5, 0, Math.PI * 2);
          ctx.fill();
        }
      });

      // 5. Draw Global POP & Middlebox Nodes
      GLOBAL_NODES.forEach((node) => {
        const pt = latLngTo3D(node.lat, node.lng, baseRadius);
        const r = rotatePoint(pt, rotation.yaw, rotation.pitch);

        // Only draw nodes on front hemisphere
        if (r.z > -baseRadius * 0.15) {
          const sx = centerX + r.x;
          const sy = centerY - r.y;
          const isSelected = selectedNode?.id === node.id;

          if (node.status === 'blocked') {
            // Pulsing Middlebox Warning Rings
            const ringRadius = 8 + Math.sin(animPulse * 2) * 5;
            ctx.strokeStyle = 'rgba(239, 68, 68, 0.75)';
            ctx.lineWidth = 1.5;
            ctx.beginPath();
            ctx.arc(sx, sy, ringRadius, 0, Math.PI * 2);
            ctx.stroke();

            ctx.fillStyle = '#ef4444';
            ctx.beginPath();
            ctx.arc(sx, sy, 5, 0, Math.PI * 2);
            ctx.fill();
          } else {
            // Active POP Node
            ctx.fillStyle = node.latencyMs < 50 ? '#10b981' : node.latencyMs < 150 ? '#f59e0b' : '#3b82f6';
            ctx.beginPath();
            ctx.arc(sx, sy, isSelected ? 6 : 4, 0, Math.PI * 2);
            ctx.fill();

            if (isSelected) {
              ctx.strokeStyle = '#38bdf8';
              ctx.lineWidth = 2;
              ctx.beginPath();
              ctx.arc(sx, sy, 9, 0, Math.PI * 2);
              ctx.stroke();
            }
          }

          // Node Label
          ctx.font = isSelected ? 'bold 11px monospace' : '10px monospace';
          ctx.fillStyle = isSelected ? '#ffffff' : 'rgba(226, 232, 240, 0.75)';
          ctx.fillText(node.name.split(' ')[0] ?? '', sx + 8, sy + 3);
        }
      });

      animationId = requestAnimationFrame(render);
    };

    render();

    return () => {
      cancelAnimationFrame(animationId);
    };
  }, [rotation, autoRotate, zoom, selectedNode]);

  // Handle Mouse Drag for 3D Orbital Rotation
  const handleMouseDown = (e: React.MouseEvent) => {
    isDraggingRef.current = true;
    lastMouseRef.current = { x: e.clientX, y: e.clientY };
  };

  const handleMouseMove = (e: React.MouseEvent) => {
    if (!isDraggingRef.current) return;
    const deltaX = e.clientX - lastMouseRef.current.x;
    const deltaY = e.clientY - lastMouseRef.current.y;
    lastMouseRef.current = { x: e.clientX, y: e.clientY };

    setRotation((prev) => ({
      yaw: prev.yaw + deltaX * 0.008,
      pitch: Math.max(-Math.PI / 2 + 0.1, Math.min(Math.PI / 2 - 0.1, prev.pitch - deltaY * 0.008)),
    }));
  };

  const handleMouseUp = () => {
    isDraggingRef.current = false;
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold flex items-center gap-3">
            <Globe className="w-7 h-7 text-sky-400" />
            Interactive 3D Network Cockpit
          </h1>
          <p className="text-slate-400 text-sm mt-1">
            Real-time WebGL visualization of global egress routing, undersea cable transit, and detected middlebox interference.
          </p>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={() => setAutoRotate(!autoRotate)}
            className={`px-3 py-1.5 rounded-lg text-xs font-mono flex items-center gap-1.5 border transition ${
              autoRotate ? 'bg-sky-950/60 border-sky-500/40 text-sky-300' : 'bg-slate-900 border-slate-700 text-slate-400'
            }`}
          >
            <RefreshCw className={`w-3.5 h-3.5 ${autoRotate ? 'animate-spin' : ''}`} />
            Auto-Orbit: {autoRotate ? 'ON' : 'PAUSED'}
          </button>
          <button
            onClick={() => setZoom((z) => Math.min(1.5, z + 0.1))}
            className="p-1.5 bg-slate-900 border border-slate-800 rounded-lg text-slate-300 hover:text-white"
          >
            <ZoomIn className="w-4 h-4" />
          </button>
          <button
            onClick={() => setZoom((z) => Math.max(0.6, z - 0.1))}
            className="p-1.5 bg-slate-900 border border-slate-800 rounded-lg text-slate-300 hover:text-white"
          >
            <ZoomOut className="w-4 h-4" />
          </button>
        </div>
      </div>

      {/* Main Cockpit Canvas & HUD */}
      <div className="grid grid-cols-1 lg:grid-cols-4 gap-6">
        {/* 3D WebGL Globe Viewport */}
        <div className="lg:col-span-3 bg-slate-950/80 border border-slate-800/80 rounded-2xl p-4 relative overflow-hidden shadow-2xl flex items-center justify-center min-h-[540px]">
          <canvas
            ref={canvasRef}
            width={760}
            height={520}
            onMouseDown={handleMouseDown}
            onMouseMove={handleMouseMove}
            onMouseUp={handleMouseUp}
            onMouseLeave={handleMouseUp}
            className="cursor-grab active:cursor-grabbing max-w-full h-auto"
          />

          {/* Floating Telemetry Badge Overlay */}
          <div className="absolute top-6 left-6 bg-slate-900/80 backdrop-blur-md border border-slate-800 rounded-xl p-3 text-xs space-y-1 font-mono">
            <div className="text-slate-400 flex items-center gap-1.5">
              <Activity className="w-3.5 h-3.5 text-emerald-400" />
              GLOBAL MESH STATUS: <span className="text-emerald-400 font-bold">OPERATIONAL</span>
            </div>
            <div className="text-slate-300">Active Cable Links: 8 Primary</div>
            <div className="text-slate-300">Egress Hops: 8 Nodes Online</div>
          </div>

          {/* Detected Middlebox Alert Banner */}
          <div className="absolute bottom-6 left-6 right-6 bg-red-950/40 backdrop-blur-md border border-red-500/30 rounded-xl p-3.5 flex items-center justify-between">
            <div className="flex items-center gap-3">
              <ShieldAlert className="w-5 h-5 text-red-400 animate-pulse" />
              <div>
                <div className="text-xs font-bold text-red-300">MIDDLEBOX INTERFERENCE DETECTED</div>
                <div className="text-xs text-red-400/80">Tehran Node: Stateful RST Injection observed on TLS SNI probe. Autonomous Antibody active.</div>
              </div>
            </div>
            <span className="text-xs font-mono bg-red-900/60 text-red-200 border border-red-700/50 px-2 py-1 rounded">
              IMMUNIZED
            </span>
          </div>
        </div>

        {/* Live HUD Sidebar */}
        <div className="space-y-4">
          {/* Node Inspector Card */}
          <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-4">
            <h3 className="text-sm font-semibold text-slate-200 flex items-center gap-2 mb-3">
              <Cpu className="w-4 h-4 text-sky-400" />
              Node Inspector
            </h3>
            {selectedNode ? (
              <div className="space-y-2.5 text-xs">
                <div>
                  <span className="text-slate-400">Target Node:</span>
                  <p className="font-mono text-white text-sm font-bold">{selectedNode.name}</p>
                </div>
                <div className="grid grid-cols-2 gap-2">
                  <div>
                    <span className="text-slate-400">Coordinates:</span>
                    <p className="font-mono text-slate-300">{selectedNode.lat.toFixed(2)}°, {selectedNode.lng.toFixed(2)}°</p>
                  </div>
                  <div>
                    <span className="text-slate-400">RTT Latency:</span>
                    <p className={`font-mono font-bold ${selectedNode.latencyMs < 50 ? 'text-emerald-400' : 'text-amber-400'}`}>
                      {selectedNode.latencyMs} ms
                    </p>
                  </div>
                </div>

                {selectedNode.interference && (
                  <div className="mt-3 p-2.5 bg-red-950/30 border border-red-900/40 rounded-lg">
                    <span className="text-red-400 font-bold block mb-1">DPI Middlebox Profile:</span>
                    <p className="text-red-300 text-[11px]">{selectedNode.interference}</p>
                    {selectedNode.antibody && (
                      <div className="mt-2 text-emerald-400 font-mono text-[11px]">
                        Active Antibody: {selectedNode.antibody}
                      </div>
                    )}
                  </div>
                )}
              </div>
            ) : (
              <p className="text-xs text-slate-500">Select a node to inspect telemetry.</p>
            )}
          </div>

          {/* Quick Node Selector */}
          <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-4">
            <h3 className="text-sm font-semibold text-slate-200 flex items-center gap-2 mb-3">
              <Layers className="w-4 h-4 text-sky-400" />
              Active Edge Nodes
            </h3>
            <div className="space-y-1.5 max-h-56 overflow-y-auto pr-1">
              {GLOBAL_NODES.map((node) => (
                <button
                  key={node.id}
                  onClick={() => setSelectedNode(node)}
                  className={`w-full text-left px-2.5 py-2 rounded-lg text-xs font-mono flex items-center justify-between border transition ${
                    selectedNode?.id === node.id
                      ? 'bg-sky-950/60 border-sky-500/50 text-white'
                      : 'bg-slate-950/40 border-slate-800/60 text-slate-400 hover:border-slate-700'
                  }`}
                >
                  <span className="truncate">{node.name.split(' ')[0] ?? ''}</span>
                  <span className={node.status === 'blocked' ? 'text-red-400' : 'text-emerald-400'}>
                    {node.status === 'blocked' ? 'DPI ALERT' : `${node.latencyMs}ms`}
                  </span>
                </button>
              ))}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

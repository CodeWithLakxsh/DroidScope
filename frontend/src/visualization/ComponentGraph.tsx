/**
 * Application component graph.
 *
 * Nodes are drawn only from parsed manifest data; no relationship is invented.
 * An edge exists when the manifest actually expresses one — a component to the
 * permission that guards it, or to the intent-filter actions it handles.
 */

import { useMemo } from 'react';
import {
  Background,
  Controls,
  MiniMap,
  ReactFlow,
  type Edge,
  type Node,
} from '@xyflow/react';
import '@xyflow/react/dist/style.css';
import type { ApkMetadata } from '@/types/api';

const KIND_COLOUR: Record<string, string> = {
  application: 'var(--accent)',
  activity: '#3b82f6',
  service: '#8b5cf6',
  receiver: '#f59e0b',
  provider: '#ef4444',
  permission: '#64748b',
};

export function buildComponentGraph(metadata: ApkMetadata): { nodes: Node[]; edges: Edge[] } {
  const nodes: Node[] = [];
  const edges: Edge[] = [];
  const components = metadata.components ?? [];

  nodes.push({
    id: 'app',
    position: { x: 0, y: 0 },
    data: { label: metadata.package_name ?? 'application' },
    style: {
      background: KIND_COLOUR.application,
      color: 'var(--accent-text)',
      border: 'none',
      borderRadius: 6,
      fontSize: 11,
      fontWeight: 600,
      padding: '6px 10px',
      width: 210,
    },
  });

  const columns: Record<string, number> = {
    activity: 0,
    'activity-alias': 0,
    service: 1,
    receiver: 2,
    provider: 3,
  };
  const counters: Record<string, number> = {};

  components.forEach((component) => {
    const column = columns[component.kind] ?? 0;
    counters[component.kind] = (counters[component.kind] ?? 0) + 1;
    const row = counters[component.kind];
    const id = `${component.kind}:${component.name}`;
    const short = component.name.split('.').pop() ?? component.name;

    nodes.push({
      id,
      position: { x: -330 + column * 230, y: 110 + row * 58 },
      data: {
        label: `${short}${component.exported ? ' ⚠' : ''}`,
      },
      style: {
        background: 'var(--surface-raised)',
        color: 'var(--text)',
        // An exported component is outlined in its severity colour; the ⚠ in
        // the label means the state is not conveyed by colour alone.
        border: `1.5px ${component.exported ? 'solid' : 'dashed'} ${
          component.exported ? KIND_COLOUR[component.kind] ?? 'var(--border)' : 'var(--border)'
        }`,
        borderRadius: 4,
        fontSize: 10,
        padding: '4px 8px',
        width: 200,
      },
    });

    edges.push({
      id: `app-${id}`,
      source: 'app',
      target: id,
      style: { stroke: 'var(--border-strong)', strokeWidth: 1 },
      animated: component.exported,
    });

    if (component.permission) {
      const permissionId = `permission:${component.permission}`;
      if (!nodes.some((node) => node.id === permissionId)) {
        nodes.push({
          id: permissionId,
          position: { x: 420, y: 110 + nodes.length * 14 },
          data: { label: component.permission.split('.').pop() ?? component.permission },
          style: {
            background: 'var(--surface-sunken)',
            color: 'var(--text-muted)',
            border: '1px solid var(--border)',
            borderRadius: 999,
            fontSize: 9,
            padding: '3px 8px',
          },
        });
      }
      edges.push({
        id: `${id}-${permissionId}`,
        source: id,
        target: permissionId,
        label: 'guarded by',
        labelStyle: { fontSize: 8, fill: 'var(--text-subtle)' },
        style: { stroke: 'var(--border)', strokeDasharray: '3 3' },
      });
    }
  });

  return { nodes, edges };
}

export function ComponentGraph({ metadata }: { metadata: ApkMetadata }) {
  const { nodes, edges } = useMemo(() => buildComponentGraph(metadata), [metadata]);

  return (
    <div style={{ height: 520 }}>
      <ReactFlow
        nodes={nodes}
        edges={edges}
        fitView
        minZoom={0.2}
        proOptions={{ hideAttribution: true }}
        nodesDraggable
        nodesConnectable={false}
        elementsSelectable
      >
        <Background color="var(--border)" gap={18} size={1} />
        <Controls showInteractive={false} />
        <MiniMap
          pannable
          zoomable
          style={{ background: 'var(--surface-sunken)' }}
          maskColor="rgba(0,0,0,0.25)"
          nodeColor={(node) => {
            const kind = String(node.id).split(':')[0];
            return KIND_COLOUR[kind] ?? 'var(--border-strong)';
          }}
        />
      </ReactFlow>
    </div>
  );
}

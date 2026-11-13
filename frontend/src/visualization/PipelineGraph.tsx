/**
 * Analysis pipeline diagram.
 *
 * Stages reflect the analyzer executions actually recorded for the scan, so the
 * diagram shows what happened rather than an idealised flow.
 */

import { useMemo } from 'react';
import { Background, Controls, ReactFlow, type Edge, type Node } from '@xyflow/react';
import '@xyflow/react/dist/style.css';
import type { AnalyzerExecution } from '@/types/api';

const STATUS_COLOUR: Record<string, string> = {
  completed: 'var(--status-ok)',
  failed: 'var(--status-error)',
  timed_out: 'var(--status-warn)',
  unavailable: 'var(--status-warn)',
  skipped: 'var(--text-subtle)',
};

const STATUS_GLYPH: Record<string, string> = {
  completed: '✓',
  failed: '✕',
  timed_out: '⏱',
  unavailable: '!',
  skipped: '·',
};

export function PipelineGraph({ executions }: { executions: AnalyzerExecution[] }) {
  const { nodes, edges } = useMemo(() => {
    const fixed = [
      { id: 'upload', label: 'APK upload' },
      { id: 'validate', label: 'Archive validation' },
      { id: 'metadata', label: 'Metadata extraction' },
    ];
    const tail = [
      { id: 'normalise', label: 'Finding normalisation' },
      { id: 'risk', label: 'Risk summary' },
      { id: 'report', label: 'Report generation' },
    ];

    const nodeList: Node[] = [];
    const edgeList: Edge[] = [];

    fixed.forEach((stage, index) => {
      nodeList.push({
        id: stage.id,
        position: { x: index * 190, y: 0 },
        data: { label: `✓ ${stage.label}` },
        style: {
          background: 'var(--surface-raised)',
          color: 'var(--text)',
          border: `1.5px solid ${STATUS_COLOUR.completed}`,
          borderRadius: 4,
          fontSize: 10,
          padding: '6px 10px',
          width: 160,
        },
      });
      if (index > 0) {
        edgeList.push({
          id: `${fixed[index - 1].id}-${stage.id}`,
          source: fixed[index - 1].id,
          target: stage.id,
          style: { stroke: 'var(--border-strong)' },
        });
      }
    });

    executions.forEach((execution, index) => {
      const id = `analyzer:${execution.analyzer}`;
      nodeList.push({
        id,
        position: { x: index * 190, y: 120 },
        data: {
          label: `${STATUS_GLYPH[execution.status] ?? '·'} ${execution.analyzer} (${execution.findings_count})`,
        },
        style: {
          background: 'var(--surface-raised)',
          color: 'var(--text)',
          border: `1.5px solid ${STATUS_COLOUR[execution.status] ?? 'var(--border)'}`,
          borderRadius: 4,
          fontSize: 10,
          padding: '6px 10px',
          width: 170,
        },
      });
      edgeList.push({
        id: `metadata-${id}`,
        source: 'metadata',
        target: id,
        style: { stroke: 'var(--border)' },
      });
      edgeList.push({
        id: `${id}-normalise`,
        source: id,
        target: 'normalise',
        style: { stroke: 'var(--border)' },
      });
    });

    tail.forEach((stage, index) => {
      nodeList.push({
        id: stage.id,
        position: { x: index * 190, y: 250 },
        data: { label: stage.label },
        style: {
          background: 'var(--surface-raised)',
          color: 'var(--text)',
          border: '1.5px solid var(--accent)',
          borderRadius: 4,
          fontSize: 10,
          padding: '6px 10px',
          width: 170,
        },
      });
      if (index > 0) {
        edgeList.push({
          id: `${tail[index - 1].id}-${stage.id}`,
          source: tail[index - 1].id,
          target: stage.id,
          style: { stroke: 'var(--border-strong)' },
        });
      }
    });

    return { nodes: nodeList, edges: edgeList };
  }, [executions]);

  return (
    <div style={{ height: 420 }}>
      <ReactFlow
        nodes={nodes}
        edges={edges}
        fitView
        minZoom={0.3}
        proOptions={{ hideAttribution: true }}
        nodesConnectable={false}
      >
        <Background color="var(--border)" gap={18} size={1} />
        <Controls showInteractive={false} />
      </ReactFlow>
    </div>
  );
}

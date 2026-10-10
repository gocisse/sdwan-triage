import { describe, it, expect } from 'vitest';
import { issueKnowledgeBase } from './knowledgeBase';
import { GLOSSARY } from '../components/Glossary';

// Phase 4.46: retransmission-derived UI text must not state packet loss as
// established. The `packet_loss` knowledge entry is rendered for a metric that
// counts TCP retransmissions, so it is held to the same standard. Keys stay stable.

const CONFIRMED_LOSS =
  /(packets? (are|were|is) (being )?(lost|dropped)|retransmissions? indicat\w* packet loss|indicat\w* (network )?packet loss|significant packet loss detected|is losing packets)/i;
const HEDGED = /(whether|if|because|or|that)\s+(the\s+)?(original\s+)?packets?\s+(were|was)\s+(lost|dropped)/gi;

function stripHedges(s: string): string {
  return s.replace(HEDGED, '');
}

function entryText(key: string): string {
  const e = issueKnowledgeBase[key];
  return [e.what, e.why, e.eli5, ...e.how].join('\n');
}

describe('retransmission wording', () => {
  it('keeps knowledge-base keys stable', () => {
    expect(issueKnowledgeBase.packet_loss).toBeDefined();
    expect(issueKnowledgeBase.tcp_retransmission).toBeDefined();
  });

  it.each(['tcp_retransmission', 'packet_loss'])('%s entry does not assert loss from retransmissions', (key) => {
    const text = stripHedges(entryText(key));
    expect(text).not.toMatch(CONFIRMED_LOSS);
  });

  it('packet_loss entry says retransmissions do not confirm loss', () => {
    expect(issueKnowledgeBase.packet_loss.what).toMatch(/do not by themselves confirm/i);
  });

  it('glossary retransmission does not equate retransmission with loss', () => {
    const def = stripHedges(GLOSSARY.retransmission.definition);
    expect(def).not.toMatch(CONFIRMED_LOSS);
    expect(GLOSSARY.retransmission.definition).toMatch(/does not show which|not show which/i);
  });
});

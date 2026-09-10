(function (root) {
  'use strict';

  const boundary = 'Only the explicitly filtered records are included. This is not a comprehensive actor profile, an attribution verdict, a detection rule, or a measure of defensive coverage or maturity.';
  const csvSafety = 'Spreadsheet-sensitive display cells are apostrophe-prefixed. record_json preserves original values. source_metadata_json preserves the source snapshot metadata.';
  const clone = (value) => JSON.parse(JSON.stringify(value));

  function createEnvelope(data, recordIds, filters, buildContext, exportedAt = new Date().toISOString()) {
    if (!buildContext || !/^[a-f0-9]{40}$/.test(buildContext.revision || '') || !/^[a-f0-9]{64}$/.test(buildContext.source_dataset_sha256 || '') || buildContext.release_id !== data.source_system.release_id) {
      throw new Error('Verified snapshot build context is required for an evidence handoff.');
    }
    if (!Array.isArray(recordIds) || !recordIds.length || new Set(recordIds).size !== recordIds.length) throw new Error('Select a non-empty set of unique evidence IDs.');
    const index = new Map();
    for (const actor of data.actors) {
      const { evidence, ...actorContext } = actor;
      for (const record of evidence) {
        if (Object.prototype.hasOwnProperty.call(record, 'actor')) throw new Error('Source field conflicts with export actor context. No fields were discarded.');
        if (index.has(record.id)) throw new Error('Duplicate source evidence ID.');
        index.set(record.id, { ...record, actor: actorContext });
      }
    }
    const records = recordIds.map((id) => {
      if (!index.has(id)) throw new Error('A selected evidence ID is absent from the source snapshot.');
      return clone(index.get(id));
    });
    const { actors, ...sourceMetadata } = data;
    return {
      schema_version: '1.1.0',
      export_scope: 'current filters',
      exported_at: exportedAt,
      export_time_notice: 'Export time is not a publication date or an analyst-review date.',
      selection: { mode: 'filtered-records', filters: clone(filters), record_ids: [...recordIds] },
      reuse_boundary: boundary,
      build_context: clone(buildContext),
      source_release: clone(data.source_system),
      source_dataset_metadata: clone(sourceMetadata),
      framework: clone(data.framework),
      result_count: records.length,
      records
    };
  }

  function csvCell(value) {
    let text = typeof value === 'object' && value !== null ? JSON.stringify(value) : String(value ?? '');
    // Quoting alone does not stop a spreadsheet from interpreting a formula.
    if (/^[\s\u0000-\u001f\u007f-\u009f\u200b-\u200f\u202a-\u202e\u2060-\u206f\ufeff]*[=+@-]/u.test(text) || /^[\t\r\n]/.test(text)) text = "'" + text;
    return '"' + text.replace(/"/g, '""') + '"';
  }

  function toCsv(payload) {
    // Preserve the existing column prefix, then append provenance and lossless JSON.
    const headers = ['actor', 'actor_id', 'campaign', 'technique_id', 'technique', 'tactics', 'framework_version', 'framework_stix_id', 'mapping_status', 'confidence', 'confidence_rationale', 'lifecycle_state', 'correction_state', 'actor_version', 'campaign_version', 'technique_version', 'first_observed', 'last_observed', 'notes', 'uncertainty', 'source_urls', 'evidence_id', 'claim_review_state', 'claim_reviewed_at', 'claim_version', 'claim_rationale', 'claim_correction_note', 'source_locators_json', 'source_release_id', 'source_dataset_version', 'source_released_at', 'upstream_revision', 'source_dataset_sha256', 'exported_at', 'selection_json', 'reuse_boundary', 'record_json', 'source_metadata_json', 'build_context_json', 'csv_safety_note'];
    const rows = payload.records.map((record) => [
      record.actor.name, record.actor.id, record.campaign?.name, record.technique_id, record.technique,
      record.tactics.join('; '), record.framework_reference.version, record.framework_reference.stix_id,
      record.mapping_status, record.confidence, record.confidence_rationale,
      record.record_lifecycle.state, record.record_lifecycle.correction_state,
      record.record_lifecycle.actor_version, record.record_lifecycle.campaign_version, record.record_lifecycle.technique_version,
      record.first_observed, record.last_observed, record.notes, record.uncertainty,
      record.sources.map((source) => source.url).join('; '), record.id,
      record.claim_review?.state, record.claim_review?.reviewed_at, record.claim_review?.version,
      record.claim_review?.rationale, record.claim_review?.correction_note, record.source_locators,
      payload.source_release.release_id, payload.source_release.dataset_version, payload.source_release.released_at,
      payload.build_context.revision, payload.build_context.source_dataset_sha256, payload.exported_at,
      payload.selection, payload.reuse_boundary, record, payload.source_dataset_metadata, payload.build_context, csvSafety
    ]);
    return '\uFEFF' + [headers, ...rows].map((row) => row.map(csvCell).join(',')).join('\r\n') + '\r\n';
  }

  function markdownText(value) {
    return String(value ?? 'Not recorded').replace(/\r\n?/g, '\n')
      .replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f\u200b-\u200f\u202a-\u202e\u2060-\u206f\ufeff]/g, (character) => '\\u' + character.charCodeAt(0).toString(16).padStart(4, '0'))
      .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
      .replace(/([\\`*_{}\[\]()#+.!|~-])/g, '\\$1');
  }

  function markdownLink(label, value) {
    const text = markdownText(label);
    try {
      if (typeof value !== 'string' || /[\u0000-\u0020\u007f]/.test(value)) throw new Error('Invalid URL');
      const url = new URL(value);
      if (url.protocol !== 'https:' || url.username || url.password) throw new Error('Unsafe URL');
      const destination = url.href.replace(/[()<>\\]/g, (character) => '%' + character.charCodeAt(0).toString(16).toUpperCase());
      return '[' + text + '](<' + destination + '>)';
    } catch {
      return text + ' - URL not linked: ' + markdownText(value);
    }
  }

  function toMarkdown(payload) {
    const line = (label, value) => '- ' + label + ': ' + markdownText(value);
    const paragraph = (value) => markdownText(value).split('\n').map((part) => '> ' + part).join('\n');
    const lines = [
      '# HECAVEX source-linked evidence brief', '', payload.reuse_boundary, '',
      '## Snapshot and selection', '',
      line('Selected mappings', payload.result_count),
      line('Filters', JSON.stringify(payload.selection.filters)),
      line('Exact evidence IDs', payload.selection.record_ids.join(', ')),
      line('Frozen APT dataset release', payload.source_release.release_id),
      line('Dataset version', payload.source_release.dataset_version),
      line('Publication time', payload.source_release.released_at),
      line('Pinned APT build revision', payload.build_context.revision),
      line('Source JSON SHA-256', payload.build_context.source_dataset_sha256),
      line('Export time', payload.exported_at),
      line('ATT&CK framework version', payload.framework.version), '',
      payload.export_time_notice + ' The pinned build revision does not establish a separate review of any claim. Current web addresses may later contain a newer release.', '',
      markdownLink('Canonical Labs source JSON', payload.build_context.source_dataset_url), '',
      'The canonical procedure and provenance text below remains English. Source rights and analytical limitations still apply. Keep the JSON export for the complete machine-readable fields.', ''
    ];
    for (const record of payload.records) {
      lines.push('## ' + markdownText(record.actor.name) + ' / ' + markdownText(record.technique_id), '',
        line('Evidence ID', record.id), line('Technique', record.technique), line('Campaign', record.campaign?.name),
        line('Evidence status', record.mapping_status), line('Published confidence', record.confidence),
        line('Confidence basis', record.confidence_rationale), line('First observed', record.first_observed), line('Last observed', record.last_observed),
        line('Claim assessment method', record.assessment?.method), line('Source comparison date (not human review)', record.assessment?.compared_at),
        line('Evidence type', record.assessment?.evidence_type), line('Confidence scope', record.assessment?.confidence_scope),
        line('Source dependence', record.assessment?.source_dependence), line('Mapping rationale', record.assessment?.mapping_rationale),
        line('Alternative explanations', record.assessment?.alternatives?.join(' / ')),
        line('Date basis', record.temporal_scope?.date_basis), line('Time limitation', record.temporal_scope?.note),
        line('Source publication date', record.temporal_scope?.source_published_at), line('Activity first / last', [record.temporal_scope?.activity_first || 'Not recorded', record.temporal_scope?.activity_last || 'Not recorded'].join(' / ')),
        line('Actor / campaign / technique versions', [record.record_lifecycle.actor_version, record.record_lifecycle.campaign_version, record.record_lifecycle.technique_version].join(' / ')),
        line('Upstream lifecycle', record.record_lifecycle.state), line('Correction state', record.record_lifecycle.correction_state),
        line('Actor review date', record.actor.last_reviewed), '', '### Published procedure', '', paragraph(record.notes), '',
        '### Claim review and limitations', '', line('Claim review state', record.claim_review?.state),
        line('Independent claim review date', record.claim_review?.reviewed_at), line('Claim version', record.claim_review?.version),
        line('Claim-review rationale', record.claim_review?.rationale), line('Claim correction note', record.claim_review?.correction_note || 'Not recorded'), '',
        paragraph(record.uncertainty), '', '### Public sources and exact locators', '');
      for (const source of record.sources) {
        lines.push('- ' + markdownLink(source.title, source.url), '  ' + line('Source ID / publisher / publication date', [source.id, source.publisher, source.published].join(' / ')),
          '  ' + markdownLink('APT Notes source record', source.apt_notes_url));
        const locators = (record.source_locators || []).filter((locator) => locator.source === source.id);
        if (source.source_identity) lines.push('  ' + line('Source edition', source.source_identity.edition), '  ' + line('Access date / outcome', [source.source_identity.accessed_at, source.source_identity.access_outcome].join(' / ')), '  ' + line('Source body SHA-256', source.source_identity.body_sha256), '  ' + line('Preservation boundary', source.source_identity.preservation));
        if (!locators.length) lines.push('  - Exact source locator: Not recorded');
        for (const locator of locators) lines.push('  ' + line('Locator', locator.locator), '  ' + line('Locator basis', locator.basis), '  ' + line('Locator checked at (not claim review)', locator.checked_at));
      }
      lines.push('', markdownLink('Actor dossier', record.actor.url), markdownLink('APT Notes technique record', record.apt_notes_url));
      if (record.campaign?.url) lines.push(markdownLink('Campaign record', record.campaign.url));
      lines.push('');
    }
    lines.push('## Reuse boundary', '', 'Compare the published procedure with your own environment and the original source before drawing a defensive conclusion. No detection efficacy, current activity or actor-wide completeness is inferred.', '',
      markdownLink('HECAVEX data licensing', 'https://labs.hecavex.com/licence/'), markdownLink('MITRE ATT&CK terms', payload.framework.terms), '');
    return lines.join('\n');
  }

  const api = { createEnvelope, toCsv, toMarkdown, csvCell, markdownText, markdownLink };
  if (typeof module === 'object' && module.exports) module.exports = api;
  else root.HECAVEX_EVIDENCE_EXPORT = Object.freeze(api);
})(typeof window === 'object' ? window : globalThis);

// Full MetaDefender responses list 20+ engines each; these helpers keep the parts an
// assistant actually needs so a single lookup doesn't flood the context window.

export function summarizeScan(r: any) {
  const scan = r?.scan_results ?? {};
  const details: Record<string, any> = scan.scan_details ?? {};
  const detections = Object.entries(details)
    .filter(([, d]) => d?.threat_found)
    .map(([engine, d]) => ({ engine, threat: d.threat_found }));
  return {
    data_id: r?.data_id,
    sandbox_id: r?.sandbox_id,
    file: r?.file_info
      ? {
          name: r.file_info.display_name,
          type: r.file_info.file_type_description,
          size: r.file_info.file_size,
          sha256: r.file_info.sha256,
          md5: r.file_info.md5,
        }
      : undefined,
    verdict: scan.scan_all_result_a,
    progress_percentage: scan.progress_percentage,
    detected_by: scan.total_detected_avs,
    total_engines: scan.total_avs,
    detections,
    threat_name: r?.threat_name,
    malware_family: r?.malware_family,
    malware_type: r?.malware_type,
    sanitized: r?.sanitized
      ? { result: r.sanitized.result, file_path: r.sanitized.file_path, reason: r.sanitized.reason }
      : undefined,
    last_scanned: scan.start_time,
  };
}

export function summarizeReputation(r: any) {
  const lookup = r?.lookup_results ?? {};
  const sources: any[] = lookup.sources ?? [];
  return {
    address: r?.address,
    detected_by: lookup.detected_by,
    start_time: lookup.start_time,
    flagged_sources: sources
      .filter((s) => s.assessment && s.assessment.toLowerCase() !== "trustworthy")
      .map((s) => ({ provider: s.provider, assessment: s.assessment, category: s.category, updated: s.update_time })),
    total_sources: sources.length,
    geo: r?.geo_info
      ? { country: r.geo_info.country?.name, city: r.geo_info.city?.name, isp: r.geo_info.isp }
      : undefined,
  };
}

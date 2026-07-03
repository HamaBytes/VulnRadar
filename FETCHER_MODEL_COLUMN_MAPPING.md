# Fetcher → ORM Column Mapping

This report maps the fetcher/enrichment output keys to the SQLAlchemy ORM model tables and columns that are actually persisted by `src/services/Database/storage.py`.

## Sources covered
- `src/fetchers/epss_fetcher_async.py`
- `src/fetchers/exploit_fetcher_async.py`
- `src/fetchers/osv_fetcher_async.py`
- `src/fetchers/github_advisory_fetcher_async.py`
- `src/fetchers/vendor_advisory_fetcher_async.py`
- `src/fetchers/nvd_fetcher_async.py`
- `src/fetchers/kev_fetcher_async.py`
- `src/services/enrichment.py`
- `src/services/Database/storage.py`

## Summary
- `Epss` is populated from EPSS fetchers.
- `ExploitReference` is populated from exploit-intel fetchers.
- `OsvRecord` / `OsvReference` are populated from OSV fetchers.
- `GithubAdvisory` / `GithubAdvisoryReference` are populated from GitHub Advisory fetchers.
- `VendorAdvisory` is populated from vendor advisory fetchers.
- `Cve`, `CveTag`, `CveDescription`, `CveReference`, CVSS tables, `CveWeakness`, and configuration tables are populated from NVD/KEV enrichment.

## Table-by-table mapping

### `epss`
| Column | Filled by fetcher? | Source field |
|---|---|---|
| `id` | No (auto) | n/a |
| `cve_db_id` | Yes | from persisted `Cve.id` |
| `cve_id` | Yes | input record `cveID` |
| `epss_score` | Yes | `epss_score` added by `enrich_records_with_epss()` |
| `percentile` | Yes | `epss_percentile` added by `enrich_records_with_epss()` |

### `exploit_references`
| Column | Filled by fetcher? | Source field / note |
|---|---|---|
| `id` | No (auto) | n/a |
| `cve_db_id` | Yes | `Cve.id` |
| `cve_id` | Yes | input record `cveID` |
| `source` | Yes | `exp_ref['source']` from exploit fetchers |
| `url` | Yes | `exp_ref['url']` or `exp_ref['link']` |
| `exploit_id` | Yes | `exp_ref['exploit_id']` or `exp_ref['id']` |
| `title` | Yes | `exp_ref['title']` or `exp_ref['name']` |
| `module` | No model column | storage still passes `module=exp_ref.get('module')`, but `src/models/exploit.py` does not define it.

### `osv_records`
| Column | Filled by fetcher? | Source field |
|---|---|---|
| `id` | No (auto) | n/a |
| `cve_db_id` | Yes | `Cve.id` |
| `cve_id` | Yes | input record `cveID` |
| `osv_id` | Yes | fetcher output `osv_id` |
| `summary` | Yes | fetcher output `osv_summary` |
| `severities` | Yes | fetcher output `osv_severities` |
| `created_at` | No (auto) | n/a |

### `osv_references`
| Column | Filled by fetcher? | Source field |
|---|---|---|
| `id` | No (auto) | n/a |
| `osv_record_id` | Yes | parent `OsvRecord.id` |
| `url` | Yes | `ref['url']` from OSV data |
| `source_id` | Yes | `ref['id']` from OSV data |
| `title` | Yes | `ref['title']` from OSV data |

### `github_advisories`
| Column | Filled by fetcher? | Source field |
|---|---|---|
| `id` | No (auto) | n/a |
| `cve_db_id` | Yes | `Cve.id` |
| `cve_id` | Yes | input record `cveID` |
| `summary` | Yes | fetcher output `github_advisory_summary` |
| `severity` | Yes | fetcher output `github_advisory_severity` |
| `package_name` | Yes | fetcher output `github_advisory_package` |
| `created_at` | No (auto) | n/a |

### `github_advisory_references`
| Column | Filled by fetcher? | Source field |
|---|---|---|
| `id` | No (auto) | n/a |
| `github_advisory_id` | Yes | parent `GithubAdvisory.id` |
| `url` | Yes | `ref['url']` from GitHub Advisory |
| `source` | Yes | `ref['source']` or default `GitHub Advisory` |

### `vendor_advisories`
| Column | Filled by fetcher? | Source field |
|---|---|---|
| `id` | No (auto) | n/a |
| `cve_db_id` | Yes | `Cve.id` |
| `cve_id` | Yes | input record `cveID` |
| `vendor` | No | not populated by current vendor-advisory fetcher output |
| `is_available` | Yes | `vendor_advisory_available` |
| `sources` | Yes | `vendor_advisory_sources` |
| `details` | Yes | `vendor_advisory_details` |
| `created_at` | No (auto) | n/a |

### `cves`
| Column | Filled by fetcher / pipeline? | Source field |
|---|---|---|
| `id` | No (auto) | n/a |
| `cve_id` | Yes | input record `cveID` |
| `source_identifier` | Yes | `vendorProject` or NVD `sourceIdentifier` |
| `title` | Yes | `vulnerabilityName` / `title` / `shortDescription` / NVD description fallback |
| `description` | Yes | `description` / `shortDescription` / `vulnerabilityName` / `summary` / `osv_summary` |
| `cvss_v3_score` | Yes | `nvd_base_score` or `cvss_v3_score` or `base_score` |
| `severity` | Yes | `nvd_base_severity` or `severity` or GitHub severity |
| `published_date` | Yes | `nvd_published` or `dateAdded` or `published_date` |
| `last_modified_date` | Yes | `nvd_last_modified` or `last_modified_date` |
| `vuln_status` | Yes | `nvd_vuln_status` or `vuln_status` |
| `created_at` | No (auto) | n/a |

### `cve_tags`
These are inferred values, not direct fetcher columns.
| Column | Filled by pipeline? | Basis |
|---|---|---|
| `id` | No (auto) | n/a |
| `cve_db_id` | Yes | `Cve.id` |
| `value` | Yes | derived from:
- `vendorProject`
- `product`
- `knownRansomwareCampaignUse`
- `has_exploit`
- `epss_score`
- `kev`
- `osv_summary`
- `github_advisory_summary`
- `exploit_sources`
- `additional_tags`

### `cve_references`
| Column | Filled by fetcher / pipeline? | Source field |
|---|---|---|
| `id` | No (auto) | n/a |
| `cve_db_id` | Yes | `Cve.id` |
| `url` | Yes | extracted from:
- `notes` / `notes_text`
- `external_references`
- `nvd_cve.references` |
| `source` | Yes | set to `notes`, `external`, or NVD source |

### `cve_descriptions`
| Column | Filled by fetcher? | Source field |
|---|---|---|
| `id` | No (auto) | n/a |
| `cve_db_id` | Yes | `Cve.id` |
| `lang` | Yes | from NVD description item |
| `value` | Yes | from NVD description item |

### `cvss_metric_v2` / `cvss_data_v2`
Filled by NVD data only.
- `CvssMetricV2` columns: `source`, `metric_type`, `base_severity`, `exploitability_score`, `impact_score`, `ac_insuf_info`, `obtain_all_privilege`, `obtain_user_privilege`, `obtain_other_privilege`, `user_interaction_required`
- `CvssDataV2` columns: `version`, `vector_string`, `base_score`, `access_vector`, `access_complexity`, `authentication`, `confidentiality_impact`, `integrity_impact`, `availability_impact`

### `cvss_metric_v31` / `cvss_data_v31`
Filled by NVD data only.
- `CvssMetricV31` columns: `source`, `metric_type`, `exploitability_score`, `impact_score`
- `CvssDataV31` columns: `version`, `vector_string`, `base_score`, `base_severity`, `attack_vector`, `attack_complexity`, `privileges_required`, `user_interaction`, `scope`, `confidentiality_impact`, `integrity_impact`, `availability_impact`

### `cvss_metric_v40` / `cvss_data_v40`
Filled by NVD data only.
- `CvssMetricV40` columns: `source`, `metric_type`
- `CvssDataV40` columns: `version`, `vector_string`, `base_score`, `base_severity`, `attack_vector`, `attack_complexity`, `attack_requirements`, `privileges_required`, `user_interaction`, `vuln_confidentiality_impact`, `vuln_integrity_impact`, `vuln_availability_impact`

#### Note:
- The fetcher dataclass `CvssDataV40` includes `sub_confidentiality_impact`, `sub_integrity_impact`, and `sub_availability_impact`, but the ORM model `src/models/cvss_models.py` no longer defines these columns.
- The storage code still attempts to persist these `sub_*` fields to `CvssDataV40`, which is a mismatch with the current model.

### `cve_weaknesses` / `cve_weakness_descriptions`
| Column | Filled by fetcher / pipeline? | Source field |
|---|---|---|
| `source` | Yes | NVD weakness source or `KEV` if NVD weaknesses absent |
| `weakness_type` | Yes | NVD weakness type or `cwe` from `record['cwes']` |
| descriptions | Yes | weakness description values from NVD or `cwe` itself for KEV fallback |

### `cve_configurations`, `cve_nodes`, `cpe_matches`
Filled by NVD configuration data only.
- `CveConfiguration`: parent relation only.
- `CveNode`: `operator`, `negate`
- `CpeMatch`: `vulnerable`, `criteria`, `match_criteria_id`

## Columns that are not filled by current fetchers

### Model-only / auto columns
- All `id` primary keys in all tables.
- `created_at` timestamps in `OsvRecord`, `GithubAdvisory`, `VendorAdvisory`.
- `SyncState` / `SyncRun` columns are managed by sync bookkeeping, not by these fetchers.

### ORM model columns present but not populated by fetcher outputs
- `vendor_advisories.vendor` is not populated by the current vendor advisory fetcher.
- `exploit_references.module` is referenced by storage but not defined in `src/models/exploit.py`.
- `cvss_data_v40.sub_confidentiality_impact`, `sub_integrity_impact`, `sub_availability_impact` are present in the NVD dataclass but not in the ORM table.
- `Cve.created_at` is auto-managed and not sourced from fetchers.
- `CveTag.value` is derived, not directly fetched.
- `CveReference.source` is assigned in storage, but not directly provided by fetchers for all reference types.

## Observations and risks
- There is a clear mismatch between the exploit persistence logic and the `ExploitReference` model: `module` is still passed into the constructor but the model has dropped that column.
- There is also a mismatch for CVSS v4.0 `sub_*` fields: the dataclass still carries them, but the ORM table has been cleaned.
- `VendorAdvisory.vendor` should be set by vendor advisory enrichment if the table is to capture vendor identity.

## Recommended cleanup actions
1. Align `src/services/Database/storage.py` with `src/models/exploit.py` by removing `module=exp_ref.get('module')` or restoring the `module` column in the model/migration.
2. Align `src/models/cvss_models.py` and `src/services/Database/storage.py` for `sub_*` CVSS v4 fields: either preserve the columns or stop persisting them.
3. Populate `vendor_advisories.vendor` from fetcher metadata if vendor-specific advisory data is expected.

---

This report is based on the current code paths in `src/fetchers/*`, `src/services/enrichment.py`, `src/services/Database/storage.py`, and the ORM model definitions in `src/models/*.py`.
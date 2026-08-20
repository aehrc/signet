/*
 * Copyright © 2026, Commonwealth Scientific and Industrial Research Organisation
 * (CSIRO) ABN 41 687 119 230. Licensed under the Apache License, Version 2.0.
 */

/**
 * Author: John Grimes
 */

export { evaluatePolicy } from "./evaluate.js";
export {
  parseScopePattern,
  scopeMatchesIntersects,
  scopeMatchesWithin,
} from "./pattern.js";
export {
  AIDBOX_PRESET,
  FIRELY_PRESET,
  ONTOSERVER_PRESET,
  PATHLING_PRESET,
  POLICY_PRESETS,
  SMART_BASELINE_PRESET,
  SMILE_CDR_PRESET,
  type PolicyPreset,
  type PresetReference,
} from "./presets.js";
export {
  isTemplateFilterName,
  parseTemplate,
  renderTemplate,
  renderTemplateValue,
  TEMPLATE_FILTER_NAMES,
  TEMPLATE_FILTERS_REQUIRING_ARGUMENT,
  TEMPLATE_FILTERS_WITHOUT_ARGUMENT,
  type ParsedTemplate,
  type TemplateFilter,
  type TemplateInterpolationSegment,
  type TemplateLiteralSegment,
  type TemplateScope,
  type TemplateSegment,
} from "./template.js";
export { validatePolicy } from "./validate.js";
export type {
  ClaimRule,
  ClientType,
  ContextRule,
  DeniedScope,
  EvaluationClient,
  EvaluationContext,
  EvaluationEndpoint,
  EvaluationUser,
  GrantType,
  ParsedScopePattern,
  PolicyDefaults,
  PolicyDocument,
  PolicyEvaluation,
  PolicyIssue,
  PolicyValidation,
  RuleCondition,
  RuleMetadata,
  ScopeGrantRule,
  ScopeMappingRule,
  ScopePattern,
  TemplateValue,
} from "./types.js";

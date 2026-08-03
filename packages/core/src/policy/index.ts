export { evaluatePolicy } from "./evaluate.js";
export {
  parseScopePattern,
  scopeMatchesIntersects,
  scopeMatchesWithin,
} from "./pattern.js";
export {
  PATHLING_PRESET,
  POLICY_PRESETS,
  SMART_BASELINE_PRESET,
  type PolicyPreset,
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

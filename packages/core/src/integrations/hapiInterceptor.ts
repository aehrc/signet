/*
 * Copyright © 2026, Commonwealth Scientific and Industrial Research Organisation
 * (CSIRO) ABN 41 687 119 230. Licensed under the Apache License, Version 2.0.
 */

/**
 * The other side of the handshake, for HAPI FHIR.
 *
 * HAPI FHIR (the open-source server) has no claim contract to write a policy
 * preset against. `AuthorizationInterceptor` and `SearchNarrowingInterceptor` both
 * require the operator to write Java - `buildRuleList` and `buildAuthorizedList`
 * respectively - and neither reads a token by itself. The nearest thing to a
 * convention is the community `mcode/smart-backend-auth` interceptor, which reads
 * exactly `exp` and `scope`.
 *
 * So the useful deliverable is not a preset. It is the interceptor: Signet knows
 * the issuer, the JWKS location, the audience and the scope grammar it mints, and
 * can therefore generate the Java that consumes what it issues. The operator pastes
 * one file into their server instead of deriving it from three specifications.
 *
 * Three properties of the generated code are worth stating, because they are
 * deliberate and an operator should not have to read the Java to discover them.
 *
 * It fails closed. Every path that cannot establish a verified token returns
 * `denyAll`, including a token that verifies but carries no scope this generator
 * understands. HAPI's `AuthorizationInterceptor` is permissive by default when a
 * rule list is empty in some configurations, so the generated list always ends with
 * an explicit `denyAll`.
 *
 * It refuses scopes it cannot honour rather than approximating them. A SMART v2
 * scope may carry search parameters - `patient/Observation.rs?category=vital-signs`
 * - which restrict the scope to a subset of instances. `AuthorizationInterceptor`
 * cannot express that restriction, so the generated code skips such a scope
 * entirely. Silently granting the unrestricted form would turn a narrow grant into
 * a broad one, which is the one failure mode worth being inconvenient about.
 *
 * It does not pretend to narrow `user/` scopes. A user-context scope means "what
 * this user may see", which depends on the deployment's own model of who may see
 * what; the generated rules treat it as access to the resource type, and the header
 * comment points at `SearchNarrowingInterceptor` as the place that decision belongs.
 *
 * Author: John Grimes
 */

/** What the generated interceptor needs to know about the endpoint. */
export interface HapiInterceptorOptions {
  /** The endpoint's issuer, compared against the token's `iss`. */
  readonly issuer: string;
  /** Where the verifying keys are published. */
  readonly jwksUri: string;
  /** The FHIR base URL, compared against the token's `aud`. */
  readonly audience: string;
  /** Shown in the header comment so the file identifies what generated it. */
  readonly endpointName: string;
  /**
   * The algorithms the endpoint's published keys use.
   *
   * Listed in the generated code so the interceptor refuses a token whose header
   * names anything else. Derived from the endpoint rather than hard-coded,
   * because an endpoint configured for a resource server that only reads RS256
   * would otherwise be handed an interceptor that rejects its own tokens.
   */
  readonly algorithms?: readonly string[];
  /** Java package for the generated class. */
  readonly packageName?: string;
  /** Class name for the generated interceptor. */
  readonly className?: string;
}

/** Default Java package, chosen to be obviously placeholder-ish. */
const DEFAULT_PACKAGE = "org.example.fhir.security";

/** Default class name. */
const DEFAULT_CLASS = "SignetAuthorizationInterceptor";

/**
 * Narrows an algorithm name to something safe to paste as a Java identifier.
 *
 * The names come from the database, and a value that is not one of the
 * algorithms this project mints keys for has no business becoming code - so
 * anything else is dropped to `RS384`, which is what SMART asks for and what an
 * endpoint with no explicit choice uses. Generated source is code somebody else
 * will compile and run, and no path to it takes an unvetted string.
 *
 * @param algorithm - The stored algorithm name.
 */
function javaIdentifier(algorithm: string): string {
  return /^[A-Z]{2}\d{3}$/.test(algorithm) ? algorithm : "RS384";
}

/**
 * Escapes a value for inclusion in a Java string literal.
 *
 * Configuration values reach here from the database - an issuer, a URL, an
 * endpoint's display name - and a quotation mark in any of them would produce Java
 * that does not compile at best. Backslash first, or it would escape the escapes.
 *
 * @param value - The value to embed.
 */
function javaString(value: string): string {
  return value
    .replaceAll("\\", "\\\\")
    .replaceAll('"', String.raw`\"`)
    .replaceAll("\r", String.raw`\r`)
    .replaceAll("\n", String.raw`\n`);
}

/**
 * Generates a HAPI FHIR `AuthorizationInterceptor` for an endpoint.
 *
 * @param options - The endpoint's issuer, keys and audience.
 * @returns Java source, ready to paste into a project.
 */
export function generateHapiInterceptor(
  options: HapiInterceptorOptions,
): string {
  const packageName = options.packageName ?? DEFAULT_PACKAGE;
  const className = options.className ?? DEFAULT_CLASS;
  // Defaults to the pair SMART names, which is what an endpoint that has not
  // been configured otherwise signs with.
  const algorithmLiterals = (options.algorithms ?? ["RS384", "ES384"])
    .map((algorithm) => `JWSAlgorithm.${javaIdentifier(algorithm)}`)
    .join(", ");

  return `package ${packageName};

import java.net.URL;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Locale;

import ca.uhn.fhir.rest.api.server.RequestDetails;
import ca.uhn.fhir.rest.server.interceptor.auth.AuthorizationInterceptor;
import ca.uhn.fhir.rest.server.interceptor.auth.IAuthRule;
import ca.uhn.fhir.rest.server.interceptor.auth.RuleBuilder;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.jwk.source.RemoteJWKSet;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import org.hl7.fhir.r4.model.IdType;

/**
 * Authorises requests using access tokens issued by Signet.
 *
 * Generated for the "${javaString(options.endpointName)}" endpoint. Regenerate it
 * from the Signet console if the endpoint's issuer, keys or FHIR base URL change:
 * the values below are compile-time constants on purpose, so that a server cannot
 * be repointed at a different authorization server by editing configuration.
 *
 * Requires com.nimbusds:nimbus-jose-jwt on the classpath. Register it with
 * server.registerInterceptor(new ${className}()).
 *
 * What this file does NOT do, deliberately:
 *
 *  - It does not narrow searches. A rule permitting reads of a resource type
 *    permits reading every instance of it that the request asks for. If the
 *    deployment needs "only this practitioner's patients", that belongs in a
 *    SearchNarrowingInterceptor, which has the deployment's own model of who may
 *    see what. See
 *    https://hapifhir.io/hapi-fhir/docs/security/search_narrowing_interceptor.html
 *  - It does not honour SMART v2 scope search parameters. A scope such as
 *    patient/Observation.rs?category=vital-signs restricts access to a subset of
 *    instances that AuthorizationInterceptor cannot express, so such a scope is
 *    skipped rather than approximated as the unrestricted form.
 */
public class ${className} extends AuthorizationInterceptor {

  private static final String ISSUER = "${javaString(options.issuer)}";
  private static final String AUDIENCE = "${javaString(options.audience)}";
  private static final String JWKS_URI = "${javaString(options.jwksUri)}";

  /** Tolerated clock difference between this server and Signet, in seconds. */
  private static final long CLOCK_SKEW_SECONDS = 60L;

  private final ConfigurableJWTProcessor<SecurityContext> processor;

  public ${className}() {
    try {
      JWKSource<SecurityContext> keys = new RemoteJWKSet<>(new URL(JWKS_URI));
      ConfigurableJWTProcessor<SecurityContext> configured = new DefaultJWTProcessor<>();
      // Exactly the algorithms this endpoint publishes keys for. Listing them
      // explicitly refuses a token whose header names anything else, which is
      // the classic JWT confusion attack.
      configured.setJWSKeySelector(
          new JWSVerificationKeySelector<>(
              java.util.Set.of(${algorithmLiterals}), keys));
      this.processor = configured;
    } catch (Exception e) {
      throw new IllegalStateException("Could not initialise Signet token verification", e);
    }
  }

  @Override
  public List<IAuthRule> buildRuleList(RequestDetails theRequestDetails) {
    JWTClaimsSet claims = verifiedClaims(theRequestDetails);
    if (claims == null) {
      return denyAll("No valid access token was presented");
    }

    List<String> scopes = scopesOf(claims);
    String patientId = claimAsString(claims, "patient");

    RuleBuilder rules = new RuleBuilder();
    boolean granted = false;
    for (String scope : scopes) {
      if (applyScope(rules, scope, patientId)) {
        granted = true;
      }
    }
    if (!granted) {
      return denyAll("The access token carries no scope this server can honour");
    }

    // The final denyAll is what makes the rule list a whitelist. Without it, a
    // request matching none of the rules above would fall through to the server's
    // default behaviour rather than being refused.
    return rules.denyAll("Not permitted by the access token's scopes").build();
  }

  private List<IAuthRule> denyAll(String theMessage) {
    return new RuleBuilder().denyAll(theMessage).build();
  }

  /**
   * Verifies the bearer token and returns its claims, or null if anything is wrong.
   *
   * Signature, issuer, audience and expiry are all checked here. Returning null
   * rather than throwing keeps every failure on the same path, which is what makes
   * "fails closed" verifiable by reading one method.
   */
  private JWTClaimsSet verifiedClaims(RequestDetails theRequestDetails) {
    String header = theRequestDetails.getHeader("Authorization");
    if (header == null || !header.regionMatches(true, 0, "Bearer ", 0, 7)) {
      return null;
    }
    String token = header.substring(7).trim();
    if (token.isEmpty()) {
      return null;
    }

    try {
      JWTClaimsSet claims = this.processor.process(token, null);
      if (!ISSUER.equals(claims.getIssuer())) {
        return null;
      }
      if (claims.getAudience() == null || !claims.getAudience().contains(AUDIENCE)) {
        return null;
      }
      Date expiry = claims.getExpirationTime();
      if (expiry == null
          || expiry.getTime() + (CLOCK_SKEW_SECONDS * 1000L) < System.currentTimeMillis()) {
        return null;
      }
      return claims;
    } catch (Exception e) {
      return null;
    }
  }

  private String claimAsString(JWTClaimsSet theClaims, String theName) {
    try {
      return theClaims.getStringClaim(theName);
    } catch (Exception e) {
      return null;
    }
  }

  /** Reads the space-delimited scope claim. */
  private List<String> scopesOf(JWTClaimsSet theClaims) {
    String raw = claimAsString(theClaims, "scope");
    List<String> scopes = new ArrayList<>();
    if (raw == null) {
      return scopes;
    }
    for (String candidate : raw.split(" ")) {
      if (!candidate.isBlank()) {
        scopes.add(candidate.trim());
      }
    }
    return scopes;
  }

  /**
   * Adds the rules one scope implies.
   *
   * @return whether the scope produced any rule at all.
   */
  private boolean applyScope(RuleBuilder theRules, String theScope, String thePatientId) {
    // A scope carrying search parameters cannot be expressed as a rule; see the
    // class comment. Skipped rather than widened.
    if (theScope.indexOf('?') >= 0) {
      return false;
    }

    int slash = theScope.indexOf('/');
    int dot = theScope.lastIndexOf('.');
    if (slash <= 0 || dot <= slash + 1) {
      // Not a resource scope. openid, fhirUser, launch and offline_access carry no
      // data access, so they legitimately produce no rule.
      return false;
    }

    String context = theScope.substring(0, slash);
    String resourceType = theScope.substring(slash + 1, dot);
    String permissions = normalisePermissions(theScope.substring(dot + 1));
    if (permissions.isEmpty()) {
      return false;
    }

    // A patient-context scope without a patient in the token is meaningless: the
    // compartment it would restrict to is unknown, so nothing is granted.
    if (context.equals("patient") && (thePatientId == null || thePatientId.isBlank())) {
      return false;
    }
    if (!context.equals("patient") && !context.equals("user") && !context.equals("system")) {
      return false;
    }

    boolean readable = permissions.indexOf('r') >= 0 || permissions.indexOf('s') >= 0;
    boolean writable = permissions.indexOf('c') >= 0 || permissions.indexOf('u') >= 0;
    boolean deletable = permissions.indexOf('d') >= 0;
    boolean any = false;

    if (readable) {
      any = true;
      if (context.equals("patient")) {
        appendPatientRule(theRules, "read", resourceType, thePatientId);
      } else if (resourceType.equals("*")) {
        theRules.allow().read().allResources().withAnyId().andThen();
      } else {
        theRules.allow().read().resourcesOfType(resourceType).withAnyId().andThen();
      }
    }
    if (writable) {
      any = true;
      if (context.equals("patient")) {
        appendPatientRule(theRules, "write", resourceType, thePatientId);
      } else if (resourceType.equals("*")) {
        theRules.allow().write().allResources().withAnyId().andThen();
      } else {
        theRules.allow().write().resourcesOfType(resourceType).withAnyId().andThen();
      }
    }
    if (deletable) {
      any = true;
      if (context.equals("patient")) {
        appendPatientRule(theRules, "delete", resourceType, thePatientId);
      } else if (resourceType.equals("*")) {
        theRules.allow().delete().allResources().withAnyId().andThen();
      } else {
        theRules.allow().delete().resourcesOfType(resourceType).withAnyId().andThen();
      }
    }
    return any;
  }

  /** Adds a rule restricted to one patient's compartment. */
  private void appendPatientRule(
      RuleBuilder theRules, String theOperation, String theResourceType, String thePatientId) {
    IdType compartment = new IdType("Patient", thePatientId);
    if (theOperation.equals("read")) {
      if (theResourceType.equals("*")) {
        theRules.allow().read().allResources().inCompartment("Patient", compartment).andThen();
      } else {
        theRules
            .allow()
            .read()
            .resourcesOfType(theResourceType)
            .inCompartment("Patient", compartment)
            .andThen();
      }
    } else if (theOperation.equals("write")) {
      if (theResourceType.equals("*")) {
        theRules.allow().write().allResources().inCompartment("Patient", compartment).andThen();
      } else {
        theRules
            .allow()
            .write()
            .resourcesOfType(theResourceType)
            .inCompartment("Patient", compartment)
            .andThen();
      }
    } else {
      if (theResourceType.equals("*")) {
        theRules.allow().delete().allResources().inCompartment("Patient", compartment).andThen();
      } else {
        theRules
            .allow()
            .delete()
            .resourcesOfType(theResourceType)
            .inCompartment("Patient", compartment)
            .andThen();
      }
    }
  }

  /**
   * Normalises a permission suffix to the SMART v2 letters.
   *
   * The v1 spellings are accepted because a client library may still send them and
   * Signet may still grant them: .read becomes rs, .write becomes cud, and the bare
   * wildcard becomes all five.
   */
  private String normalisePermissions(String theSuffix) {
    String suffix = theSuffix.toLowerCase(Locale.ROOT);
    if (suffix.equals("read")) {
      return "rs";
    }
    if (suffix.equals("write")) {
      return "cud";
    }
    if (suffix.equals("*")) {
      return "cruds";
    }
    StringBuilder letters = new StringBuilder();
    for (char letter : suffix.toCharArray()) {
      if ("cruds".indexOf(letter) >= 0) {
        letters.append(letter);
      } else {
        // An unrecognised letter makes the whole suffix untrustworthy: it may mean
        // something this generator has never heard of, so nothing is granted.
        return "";
      }
    }
    return letters.toString();
  }
}
`;
}

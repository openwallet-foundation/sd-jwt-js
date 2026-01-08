import type { IntegrityMetadata } from '@sd-jwt/utils';

/**
 * Logo metadata used in rendering a credential.
 */
export type Logo = {
  /** REQUIRED. A URI pointing to the logo image. */
  uri: string;
  /** OPTIONAL. An "integrity metadata" string as described in Section 7. */
  'uri#integrity'?: IntegrityMetadata;
  /** OPTIONAL. A string containing alternative text for the logo image. */
  alt_text?: string;
};

/**
 * The simple rendering method is intended for applications that do not support SVG.
 */
export type SimpleRendering = {
  /** OPTIONAL. Logo metadata to display for the credential. */
  logo?: Logo;
  /** OPTIONAL. RGB color value for the credential background (e.g., "#FFFFFF"). */
  background_color?: string;
  /** OPTIONAL. RGB color value for the credential text (e.g., "#000000"). */
  text_color?: string;
};

/** Enum of valid values for rendering orientation. */
type Orientation = 'portrait' | 'landscape';

/** Enum of valid values for rendering color schemes. */
type ColorScheme = 'light' | 'dark';

/** Enum of valid values for rendering contrast. */
type Contrast = 'normal' | 'high';

/**
 * Properties that describe the display preferences for an SVG template rendering.
 */
export type SvgTemplateProperties = {
  /** OPTIONAL. Orientation optimized for the template. */
  orientation?: Orientation;
  /** OPTIONAL. Color scheme optimized for the template. */
  color_scheme?: ColorScheme;
  /** OPTIONAL. Contrast level optimized for the template. */
  contrast?: Contrast;
};

/**
 * SVG rendering metadata containing URI and optional integrity and properties.
 */
export type SvgTemplateRendering = {
  /** REQUIRED. A URI pointing to the SVG template. */
  uri: string;
  /** OPTIONAL. An "integrity metadata" string as described in Section 7. */
  'uri#integrity'?: IntegrityMetadata;
  /** REQUIRED if more than one SVG template is present. */
  properties?: SvgTemplateProperties;
};

/**
 * Rendering metadata, either simple or SVG-based, for a credential.
 */
export type Rendering = {
  /** OPTIONAL. Simple rendering metadata. */
  simple?: SimpleRendering;
  /** OPTIONAL. Array of SVG template rendering objects. */
  svg_template?: SvgTemplateRendering[];
};

/**
 * Display metadata associated with a credential type.
 */
export type Display = {
  /** REQUIRED. Language tag according to RFC 5646 (e.g., "en", "de"). */
  lang: string;
  /** REQUIRED. Human-readable name for the credential type. */
  name: string;
  /** OPTIONAL. Description of the credential type for end users. */
  description?: string;
  /** OPTIONAL. Rendering information (simple or SVG) for the credential. */
  rendering?: Rendering;
};

/**
 * Claim path within the credential's JSON structure.
 * Example: ["address", "street_address"]
 */
export type ClaimPath = Array<string | null>;

/**
 * Display metadata for a specific claim.
 */
export type ClaimDisplay = {
  /** REQUIRED. Language tag according to RFC 5646. */
  lang: string;
  /** REQUIRED. Human-readable label for the claim. */
  label: string;
  /** OPTIONAL. Description of the claim for end users. */
  description?: string;
};

/**
 * Indicates whether a claim is selectively disclosable.
 */
export type ClaimSelectiveDisclosure = 'always' | 'allowed' | 'never';

/**
 * Metadata for individual claims in the credential type.
 */
export type Claim = {
  /**
   * REQUIRED. Array of one or more paths to the claim in the credential subject.
   * Each path is an array of strings (or null for array elements).
   */
  path: ClaimPath;
  /** OPTIONAL. Display metadata in multiple languages. */
  display?: ClaimDisplay[];
  /** OPTIONAL. Controls whether the claim must, may, or must not be selectively disclosed. */
  sd?: ClaimSelectiveDisclosure;
  /**
   * OPTIONAL. Unique string identifier for referencing the claim in an SVG template.
   * Must consist of alphanumeric characters or underscores and must not start with a digit.
   */
  svg_id?: string;
};

/**
 * Type metadata for a specific Verifiable Credential (VC) type.
 * Reference: https://www.ietf.org/archive/id/draft-ietf-oauth-sd-jwt-vc-09.html#name-type-metadata-format
 */
export type TypeMetadataFormat = {
  /** REQUIRED. A URI uniquely identifying the credential type. */
  vct: string;
  /** OPTIONAL. Human-readable name for developers. */
  name?: string;
  /** OPTIONAL. Human-readable description for developers. */
  description?: string;
  /** OPTIONAL. URI of another type that this one extends. */
  extends?: string;
  /** OPTIONAL. Integrity metadata for the 'extends' field. */
  'extends#integrity'?: IntegrityMetadata;
  /** OPTIONAL. Array of localized display metadata for the type. */
  display?: Display[];
  /** OPTIONAL. Array of claim metadata. */
  claims?: Claim[];
};

/**
 * The resolved type metadata. If you just want to use the type metadata, you should use `typeMetadata`.
 * In case additional processing is needed (e.g. for extensions in type metadata), you can use the `typeMetadataChain`
 */
export type ResolvedTypeMetadata = {
  /**
   * The merged type metadata based on the resolved `vct` document and all `extends` values.
   */
  mergedTypeMetadata: TypeMetadataFormat;

  /**
   * The original type metadata documents, ordered from the extending type to the last extended type.
   */
  typeMetadataChain: [TypeMetadataFormat, ...TypeMetadataFormat[]];

  /**
   * The vct values present in the type metadata chain. This can be used for matching against e.g.
   * DCQL queries which can query an underlying type.
   */
  vctValues: [string, ...string[]];
};

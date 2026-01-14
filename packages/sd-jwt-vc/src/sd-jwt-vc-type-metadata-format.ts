import { z } from 'zod';

/**
 * Logo metadata used in rendering a credential.
 */
export const LogoSchema = z.looseObject({
  /** REQUIRED. A URI pointing to the logo image. */
  uri: z.string(),
  /** OPTIONAL. An "integrity metadata" string as described in Section 7. */
  'uri#integrity': z.string().optional(),
  /** OPTIONAL. A string containing alternative text for the logo image. */
  alt_text: z.string().optional(),
});

export type Logo = z.infer<typeof LogoSchema>;

/**
 * The simple rendering method is intended for applications that do not support SVG.
 */
export const SimpleRenderingSchema = z.looseObject({
  /** OPTIONAL. Logo metadata to display for the credential. */
  logo: LogoSchema.optional(),
  /** OPTIONAL. RGB color value for the credential background (e.g., "#FFFFFF"). */
  background_color: z.string().optional(),
  /** OPTIONAL. RGB color value for the credential text (e.g., "#000000"). */
  text_color: z.string().optional(),
});

export type SimpleRendering = z.infer<typeof SimpleRenderingSchema>;

/** Enum of valid values for rendering orientation. */
export const OrientationSchema = z.enum(['portrait', 'landscape']);

/** Enum of valid values for rendering color schemes. */
export const ColorSchemeSchema = z.enum(['light', 'dark']);

/** Enum of valid values for rendering contrast. */
export const ContrastSchema = z.enum(['normal', 'high']);

/**
 * Properties that describe the display preferences for an SVG template rendering.
 */
export const SvgTemplatePropertiesSchema = z.looseObject({
  /** OPTIONAL. Orientation optimized for the template. */
  orientation: OrientationSchema.optional(),
  /** OPTIONAL. Color scheme optimized for the template. */
  color_scheme: ColorSchemeSchema.optional(),
  /** OPTIONAL. Contrast level optimized for the template. */
  contrast: ContrastSchema.optional(),
});

export type SvgTemplateProperties = z.infer<typeof SvgTemplatePropertiesSchema>;

/**
 * SVG rendering metadata containing URI and optional integrity and properties.
 */
export const SvgTemplateRenderingSchema = z.looseObject({
  /** REQUIRED. A URI pointing to the SVG template. */
  uri: z.string(),
  /** OPTIONAL. An "integrity metadata" string as described in Section 7. */
  'uri#integrity': z.string().optional(),
  /** REQUIRED if more than one SVG template is present. */
  properties: SvgTemplatePropertiesSchema.optional(),
});

export type SvgTemplateRendering = z.infer<typeof SvgTemplateRenderingSchema>;

/**
 * Rendering metadata, either simple or SVG-based, for a credential.
 */
export const RenderingSchema = z.looseObject({
  /** OPTIONAL. Simple rendering metadata. */
  simple: SimpleRenderingSchema.optional(),
  /** OPTIONAL. Array of SVG template rendering objects. */
  svg_template: z.array(SvgTemplateRenderingSchema).optional(),
});

export type Rendering = z.infer<typeof RenderingSchema>;

/**
 * Display metadata associated with a credential type.
 */
export const DisplaySchema = z.looseObject({
  /** REQUIRED. Language tag according to RFC 5646 (e.g., "en", "de"). */
  lang: z.string(),
  /** REQUIRED. Human-readable name for the credential type. */
  name: z.string(),
  /** OPTIONAL. Description of the credential type for end users. */
  description: z.string().optional(),
  /** OPTIONAL. Rendering information (simple or SVG) for the credential. */
  rendering: RenderingSchema.optional(),
});

export type Display = z.infer<typeof DisplaySchema>;

/**
 * Claim path within the credential's JSON structure.
 * Example: ["address", "street_address"]
 */
export const ClaimPathSchema = z.array(z.string().nullable());

export type ClaimPath = z.infer<typeof ClaimPathSchema>;

/**
 * Display metadata for a specific claim.
 */
export const ClaimDisplaySchema = z.looseObject({
  /** REQUIRED. Language tag according to RFC 5646. */
  lang: z.string(),
  /** REQUIRED. Human-readable label for the claim. */
  label: z.string(),
  /** OPTIONAL. Description of the claim for end users. */
  description: z.string().optional(),
});

export type ClaimDisplay = z.infer<typeof ClaimDisplaySchema>;

/**
 * Indicates whether a claim is selectively disclosable.
 */
export const ClaimSelectiveDisclosureSchema = z.enum([
  'always',
  'allowed',
  'never',
]);

export type ClaimSelectiveDisclosure = z.infer<
  typeof ClaimSelectiveDisclosureSchema
>;

/**
 * Metadata for individual claims in the credential type.
 */
export const ClaimSchema = z.looseObject({
  /**
   * REQUIRED. Array of one or more paths to the claim in the credential subject.
   * Each path is an array of strings (or null for array elements).
   */
  path: ClaimPathSchema,
  /** OPTIONAL. Display metadata in multiple languages. */
  display: z.array(ClaimDisplaySchema).optional(),
  /** OPTIONAL. Controls whether the claim must, may, or must not be selectively disclosed. */
  sd: ClaimSelectiveDisclosureSchema.optional(),
  /**
   * OPTIONAL. Unique string identifier for referencing the claim in an SVG template.
   * Must consist of alphanumeric characters or underscores and must not start with a digit.
   */
  svg_id: z.string().optional(),
});

export type Claim = z.infer<typeof ClaimSchema>;

/**
 * Type metadata for a specific Verifiable Credential (VC) type.
 * Reference: https://www.ietf.org/archive/id/draft-ietf-oauth-sd-jwt-vc-09.html#name-type-metadata-format
 */
export const TypeMetadataFormatSchema = z.looseObject({
  /** REQUIRED. A URI uniquely identifying the credential type. */
  vct: z.string(),
  /** OPTIONAL. Human-readable name for developers. */
  name: z.string().optional(),
  /** OPTIONAL. Human-readable description for developers. */
  description: z.string().optional(),
  /** OPTIONAL. URI of another type that this one extends. */
  extends: z.string().optional(),
  /** OPTIONAL. Integrity metadata for the 'extends' field. */
  'extends#integrity': z.string().optional(),
  /** OPTIONAL. Array of localized display metadata for the type. */
  display: z.array(DisplaySchema).optional(),
  /** OPTIONAL. Array of claim metadata. */
  claims: z.array(ClaimSchema).optional(),
});

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

export type TypeMetadataFormat = z.infer<typeof TypeMetadataFormatSchema>;

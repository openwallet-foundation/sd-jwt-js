/**
 * https://www.ietf.org/archive/id/draft-ietf-oauth-sd-jwt-vc-08.html#name-type-metadata-format
 */
export type TypeMetadataFormat = {
  vct: string; // REQUIRED. A URI that uniquely identifies the type. This URI MUST be dereferenceable to a JSON document that describes the type.
  name?: string; // OPTIONAL. A human-readable name for the type, intended for developers reading the JSON document.
  description?: string; // OPTIONAL. A human-readable description for the type, intended for developers reading the JSON document.
  extends?: string; // OPTIONAL. A URI of another type that this type extends, as described in Section 6.4.
  'extends#Integrity'?: string; // OPTIONAL. Validating the ingegrity of the extends field
  schema?: object; // OPTIONAL. An embedded JSON Schema document describing the structure of the Verifiable Credential as described in Section 6.5.1. schema MUST NOT be used if schema_uri is present.
  schema_uri?: string; // OPTIONAL. A URL pointing to a JSON Schema document describing the structure of the Verifiable Credential as described in Section 6.5.1. schema_uri MUST NOT be used if schema is present.
  'schema_uri#Integrity'?: string; // OPTIONAL. Validating the integrity of the schema_uri field.
};

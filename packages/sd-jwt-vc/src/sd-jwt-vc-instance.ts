import { Jwt, SDJwt, SDJwtInstance, type VerifierOptions } from '@sd-jwt/core';
import {
  getListFromStatusListJWT,
  SLException,
  type StatusListJWTHeaderParameters,
  type StatusListJWTPayload,
} from '@sd-jwt/jwt-status-list';
import type {
  DisclosureFrame,
  Hasher,
  SafeVerifyResult,
  VerificationError,
  VerificationErrorCode,
  Verifier,
} from '@sd-jwt/types';
import { SDJWTException } from '@sd-jwt/utils';
import z from 'zod';
import type {
  SDJWTVCConfig,
  StatusListFetcher,
  StatusValidator,
} from './sd-jwt-vc-config';
import type { SdJwtVcPayload } from './sd-jwt-vc-payload';
import {
  type Claim,
  type ClaimPath,
  type ResolvedTypeMetadata,
  type TypeMetadataFormat,
  TypeMetadataFormatSchema,
} from './sd-jwt-vc-type-metadata-format';
import type { VerificationResult } from './verification-result';

export class SDJwtVcInstance extends SDJwtInstance<SdJwtVcPayload> {
  /**
   * The type of the SD-JWT-VC set in the header.typ field.
   */
  protected type = 'dc+sd-jwt';

  protected userConfig: SDJWTVCConfig = {};

  constructor(userConfig?: SDJWTVCConfig) {
    super(userConfig);
    if (userConfig) {
      this.userConfig = userConfig;
    }
  }

  /**
   * Validates if the disclosureFrame contains any reserved fields. If so it will throw an error.
   * @param disclosureFrame
   */
  protected validateReservedFields(
    disclosureFrame: DisclosureFrame<SdJwtVcPayload>,
  ): void {
    //validate disclosureFrame according to https://www.ietf.org/archive/id/draft-ietf-oauth-sd-jwt-vc-08.html#section-3.2.2.2
    if (
      disclosureFrame?._sd &&
      Array.isArray(disclosureFrame._sd) &&
      disclosureFrame._sd.length > 0
    ) {
      const reservedNames = ['iss', 'nbf', 'exp', 'cnf', 'vct', 'status'];
      // check if there is any reserved names in the disclosureFrame._sd array
      const reservedNamesInDisclosureFrame = (
        disclosureFrame._sd as string[]
      ).filter((key) => reservedNames.includes(key));
      if (reservedNamesInDisclosureFrame.length > 0) {
        throw new SDJWTException('Cannot disclose protected field');
      }
    }
  }

  /**
   * Fetches the status list from the uri with a timeout of 10 seconds.
   * @param uri The URI to fetch from.
   * @returns A promise that resolves to a compact JWT.
   */
  private async statusListFetcher(uri: string): Promise<string> {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 10000);

    try {
      const response = await fetch(uri, {
        signal: controller.signal,
        headers: { Accept: 'application/statuslist+jwt' },
      });
      if (!response.ok) {
        throw new Error(
          `Error fetching status list: ${
            response.status
          } ${await response.text()}`,
        );
      }

      // according to the spec the content type should be application/statuslist+jwt
      if (
        !response.headers
          .get('content-type')
          ?.includes('application/statuslist+jwt')
      ) {
        throw new Error('Invalid content type');
      }

      return response.text();
    } finally {
      clearTimeout(timeoutId);
    }
  }

  /**
   * Validates the status, throws an error if the status is not 0.
   * @param status
   * @returns
   */
  private async statusValidator(status: number): Promise<void> {
    if (status !== 0) throw new SDJWTException('Status is not valid');
    return Promise.resolve();
  }

  /**
   * Verifies the SD-JWT-VC. It will validate the signature, the keybindings when required, the status, and the VCT.
   * @param currentDate current time in seconds
   */
  async verify(encodedSDJwt: string, options?: VerifierOptions) {
    // Call the parent class's verify method
    const result: VerificationResult = await super
      .verify(encodedSDJwt, options)
      .then((res) => {
        return {
          payload: res.payload as SdJwtVcPayload,
          header: res.header,
          kb: res.kb,
        };
      });

    await this.verifyStatus(result, options);
    if (this.userConfig.loadTypeMetadataFormat) {
      const resolvedTypeMetadata = await this.fetchVct(result);
      result.typeMetadata = resolvedTypeMetadata;
    }
    return result;
  }

  /**
   * Safe verification that collects all errors instead of failing fast.
   * Returns a result object with either the verified data or an array of all errors.
   * This includes SD-JWT-VC specific validations like status and VCT metadata.
   *
   * @param encodedSDJwt - The encoded SD-JWT-VC to verify
   * @param options - Verification options
   * @returns A SafeVerifyResult containing either success data or collected errors
   */
  async safeVerify(
    encodedSDJwt: string,
    options?: VerifierOptions,
  ): Promise<SafeVerifyResult<VerificationResult>> {
    const errors: VerificationError[] = [];

    // Helper to add errors
    const addError = (
      code: VerificationErrorCode,
      message: string,
      details?: unknown,
    ) => {
      errors.push({ code, message, details });
    };

    // First, call the parent's safeVerify to get base verification results
    const baseResult = await super.safeVerify(encodedSDJwt, options);

    // Collect errors from base verification
    if (!baseResult.success) {
      errors.push(...baseResult.errors);
    }

    // Build partial result for additional verifications
    let result: VerificationResult | undefined;
    if (baseResult.success) {
      result = {
        payload: baseResult.data.payload as SdJwtVcPayload,
        header: baseResult.data.header,
        kb: baseResult.data.kb,
      };
    } else {
      // Try to extract payload even if verification failed for status/vct checks
      try {
        const { payload, header } = await SDJwt.extractJwt<
          Record<string, unknown>,
          SdJwtVcPayload
        >(encodedSDJwt);
        if (payload) {
          result = {
            payload,
            header,
            kb: undefined,
          };
        }
      } catch {
        // Cannot extract payload, skip additional checks
      }
    }

    // Verify status (if payload is available)
    if (result) {
      try {
        await this.verifyStatus(result, options);
      } catch (error) {
        const errorMessage = (error as Error).message;
        if (errorMessage.includes('Status is not valid')) {
          addError('STATUS_INVALID', errorMessage, error);
        } else {
          addError(
            'STATUS_VERIFICATION_FAILED',
            `Status verification failed: ${errorMessage}`,
            error,
          );
        }
      }

      // Verify VCT metadata (if configured)
      if (this.userConfig.loadTypeMetadataFormat) {
        try {
          const resolvedTypeMetadata = await this.fetchVct(result);
          if (result) {
            result.typeMetadata = resolvedTypeMetadata;
          }
        } catch (error) {
          addError(
            'VCT_VERIFICATION_FAILED',
            `VCT verification failed: ${(error as Error).message}`,
            error,
          );
        }
      }
    }

    // Return result
    if (errors.length > 0) {
      return { success: false, errors };
    }

    if (!result) {
      return {
        success: false,
        errors: [
          {
            code: 'INVALID_SD_JWT',
            message: 'Failed to construct verification result',
          },
        ],
      };
    }

    return {
      success: true,
      data: result,
    };
  }

  /**
   * Gets VCT Metadata of the raw SD-JWT-VC. Returns the type metadata format. If the SD-JWT-VC is invalid or does not contain a vct claim, an error is thrown.
   *
   * It may return `undefined` if the fetcher returned an undefined value (instead of throwing an error).
   *
   * @param encodedSDJwt
   * @returns
   */
  async getVct(
    encodedSDJwt: string,
  ): Promise<ResolvedTypeMetadata | undefined> {
    // Call the parent class's verify method
    const { payload, header } = await SDJwt.extractJwt<
      Record<string, unknown>,
      SdJwtVcPayload
    >(encodedSDJwt);

    if (!payload) {
      throw new SDJWTException('JWT payload is missing');
    }

    const result: VerificationResult = {
      payload,
      header,
      kb: undefined,
    };

    return this.fetchVct(result);
  }

  /**
   * Validates the integrity of the response if the integrity is passed. If the integrity does not match, an error is thrown.
   * @param integrity
   * @param response
   */
  private async validateIntegrity(
    response: Response,
    url: string,
    integrity?: string,
  ) {
    if (!integrity) return;

    // validate the integrity of the response according to https://www.w3.org/TR/SRI/
    const arrayBuffer = await response.arrayBuffer();
    const alg = integrity.split('-')[0];
    //TODO: error handling when a hasher is passed that is not supporting the required algorithm according to the spec
    const hashBuffer = await (this.userConfig.hasher as Hasher)(
      arrayBuffer,
      alg,
    );
    const integrityHash = integrity.split('-')[1];
    const hash = Array.from(new Uint8Array(hashBuffer))
      .map((byte) => byte.toString(16).padStart(2, '0'))
      .join('');
    if (hash !== integrityHash) {
      throw new Error(
        `Integrity check for ${url} failed: is ${hash}, but expected ${integrityHash}`,
      );
    }
  }

  /**
   * Fetches the content from the url with a timeout of 10 seconds.
   * @param url
   * @returns
   */
  private async fetchWithIntegrity(
    url: string,
    integrity?: string,
  ): Promise<unknown> {
    try {
      const response = await fetch(url, {
        signal: AbortSignal.timeout(this.userConfig.timeout ?? 10000),
      });
      if (!response.ok) {
        const errorText = await response.text();
        throw new Error(
          `Error fetching ${url}: ${response.status} ${response.statusText} - ${errorText}`,
        );
      }
      await this.validateIntegrity(response.clone(), url, integrity);
      const data = await response.json();

      return data;
    } catch (error) {
      if ((error as Error).name === 'TimeoutError') {
        throw new Error(`Request to ${url} timed out`);
      }
      throw error;
    }
  }

  /**
   * Verifies the VCT of the SD-JWT-VC. Returns the type metadata format.
   * Resolves the full extends chain according to spec sections 6.4, 8.2, and 9.5.
   * @param result
   * @returns
   */
  private async fetchVct(
    result: VerificationResult,
  ): Promise<ResolvedTypeMetadata | undefined> {
    const typeMetadataFormat = await this.fetchSingleVct(
      result.payload.vct,
      result.payload['vct#integrity'],
    );

    if (!typeMetadataFormat) return undefined;

    // If there's no extends
    if (!typeMetadataFormat.extends) {
      return {
        mergedTypeMetadata: typeMetadataFormat,
        typeMetadataChain: [typeMetadataFormat],
        vctValues: [typeMetadataFormat.vct],
      };
    }

    // Resolve the full VCT chain if extends is present
    return this.resolveVctExtendsChain(typeMetadataFormat);
  }

  /**
   * Checks if two claim paths are equal by comparing each element.
   * @param path1 First claim path
   * @param path2 Second claim path
   * @returns True if paths are equal, false otherwise
   */
  private claimPathsEqual(path1: ClaimPath, path2: ClaimPath): boolean {
    if (path1.length !== path2.length) return false;
    return path1.every((element, index) => element === path2[index]);
  }

  /**
   * Validates that extending claim metadata respects the constraints from spec section 9.5.1.
   * @param baseClaim The base claim metadata
   * @param extendingClaim The extending claim metadata
   * @throws SDJWTException if validation fails
   */
  private validateClaimExtension(
    baseClaim: Claim,
    extendingClaim: Claim,
  ): void {
    // Validate 'sd' property constraints (section 9.5.1)
    if (baseClaim.sd && extendingClaim.sd) {
      // Cannot change from 'always' or 'never' to a different value
      if (
        (baseClaim.sd === 'always' || baseClaim.sd === 'never') &&
        baseClaim.sd !== extendingClaim.sd
      ) {
        const pathStr = JSON.stringify(extendingClaim.path);
        throw new SDJWTException(
          `Cannot change 'sd' property from '${baseClaim.sd}' to '${extendingClaim.sd}' for claim at path ${pathStr}`,
        );
      }
    }
  }

  /**
   * Merges two type metadata formats, with the extending metadata overriding the base metadata.
   * According to spec section 9.5:
   * - All claim metadata from the extended type are inherited
   * - The child type can add new claims or properties
   * - If the child type defines claim metadata with the same path as the extended type,
   *   the child type's object will override the corresponding object from the extended type
   * According to spec section 9.5.1:
   * - sd property can only be changed from 'allowed' (or omitted) to 'always' or 'never'
   * - sd property cannot be changed from 'always' or 'never' to a different value
   * According to spec section 8.2:
   * - If the extending type defines its own display property, the original display metadata is ignored
   * Note: The spec also mentions 'mandatory' property constraints, but this is not currently
   * defined in the Claim type and will be validated when that property is added to the type.
   * @param base The base type metadata format
   * @param extending The extending type metadata format
   * @returns The merged type metadata format
   */
  private mergeTypeMetadata(
    base: TypeMetadataFormat,
    extending: TypeMetadataFormat,
  ): TypeMetadataFormat {
    // Start with a shallow copy of the extending metadata
    // All properties that don't have explicit processing logic for merging
    // will only be shallow copied, and the extending metadata will take precedence.
    const merged: TypeMetadataFormat = { ...extending };

    // Merge claims arrays if both exist
    if (base.claims || extending.claims) {
      const baseClaims = base.claims ?? [];
      const extendingClaims = extending.claims ?? [];

      // Validate extending claims that override base claims
      for (const extendingClaim of extendingClaims) {
        const matchingBaseClaim = baseClaims.find((baseClaim) =>
          this.claimPathsEqual(baseClaim.path, extendingClaim.path),
        );

        if (matchingBaseClaim) {
          this.validateClaimExtension(matchingBaseClaim, extendingClaim);
        }
      }

      // Build final claims array preserving order
      // Start with base claims, replacing any that are overridden
      const mergedClaims: typeof baseClaims = [];
      const extendedClaimsWithoutBase = [...extendingClaims];

      // Add base claims, replacing with extending version if path matches
      for (const baseClaim of baseClaims) {
        const extendingClaimIndex = extendedClaimsWithoutBase.findIndex(
          (extendingClaim) =>
            this.claimPathsEqual(baseClaim.path, extendingClaim.path),
        );
        const extendingClaim =
          extendingClaimIndex !== -1
            ? extendedClaimsWithoutBase[extendingClaimIndex]
            : undefined;

        // Remove item from the array
        if (extendingClaim) {
          extendedClaimsWithoutBase.splice(extendingClaimIndex, 1);
        }

        // Prefer extending claim, otherwise use base claim
        mergedClaims.push(extendingClaim ?? baseClaim);
      }

      // Add all remaining claims at the end
      mergedClaims.push(...extendedClaimsWithoutBase);

      merged.claims = mergedClaims;
    }

    // Handle display metadata (section 8.2)
    // If extending type doesn't define display, inherit from base
    if (!extending.display && base.display) {
      merged.display = base.display;
    }

    return merged;
  }

  /**
   * Resolves the full VCT chain by recursively fetching extended type metadata.
   * Implements security considerations from spec section 10.3 for circular dependencies.
   * @param vct The VCT URI to resolve
   * @param integrity Optional integrity metadata for the VCT
   * @param depth Current depth in the chain
   * @param visitedVcts Set of already visited VCT URIs to detect circular dependencies
   * @returns The fully resolved and merged type metadata format
   */
  private async resolveVctExtendsChain(
    parentTypeMetadata: TypeMetadataFormat,
    // We start at one, as the base is already fetched when this method is first called
    depth: number = 1,
    // By default include the parent vct, in case of the first call
    visitedVcts: Set<string> = new Set(parentTypeMetadata.vct),
  ): Promise<ResolvedTypeMetadata> {
    const maxDepth = this.userConfig.maxVctExtendsDepth ?? 5;

    // Check max depth (security consideration from spec section 10.3)
    if (maxDepth !== -1 && depth > maxDepth) {
      throw new SDJWTException(
        `Maximum VCT extends depth of ${maxDepth} exceeded`,
      );
    }

    if (!parentTypeMetadata.extends) {
      throw new SDJWTException(
        `Type metadata for vct '${parentTypeMetadata.vct}' has no 'extends' field. Unable to resolve extended type metadata document.`,
      );
    }

    // Check for circular dependencies (security consideration from spec section 10.3)
    if (visitedVcts.has(parentTypeMetadata.extends)) {
      throw new SDJWTException(
        `Circular dependency detected in VCT extends chain: ${parentTypeMetadata.extends}`,
      );
    }

    // Mark this VCT as visited
    visitedVcts.add(parentTypeMetadata.extends);

    const extendedTypeMetadata = await this.fetchSingleVct(
      parentTypeMetadata.extends,
      parentTypeMetadata['extends#integrity'],
    );

    // While top-level vct MAY return null (meaning there's no vct type metadata)
    // The extends value ALWAYS must resolve to a value. A custom user provided resolver
    // can return a minimal on-demand type metadata document if it wants to support this use case
    if (!extendedTypeMetadata) {
      throw new SDJWTException(
        `Resolving VCT extends value '${parentTypeMetadata.extends}' resulted in an undefined result.`,
      );
    }

    let resolvedTypeMetadata: ResolvedTypeMetadata;

    // If this type extends another, recursively resolve the chain
    //  We MUST first process the lower level document before processing
    // the higher level document
    if (extendedTypeMetadata.extends) {
      resolvedTypeMetadata = await this.resolveVctExtendsChain(
        extendedTypeMetadata,
        depth + 1,
        visitedVcts,
      );
    } else {
      resolvedTypeMetadata = {
        mergedTypeMetadata: extendedTypeMetadata,
        typeMetadataChain: [extendedTypeMetadata],
        vctValues: [extendedTypeMetadata.vct],
      };
    }

    const mergedTypeMetadata = this.mergeTypeMetadata(
      resolvedTypeMetadata.mergedTypeMetadata,
      parentTypeMetadata,
    );

    return {
      mergedTypeMetadata: mergedTypeMetadata,
      typeMetadataChain: [
        parentTypeMetadata,
        ...resolvedTypeMetadata.typeMetadataChain,
      ],
      vctValues: [parentTypeMetadata.vct, ...resolvedTypeMetadata.vctValues],
    };
  }

  /**
   * Fetches and verifies the VCT Metadata for a VCT value.
   * @param result
   * @returns
   */
  private async fetchSingleVct(
    vct: string,
    integrity?: string,
  ): Promise<TypeMetadataFormat | undefined> {
    const fetcher =
      this.userConfig.vctFetcher ??
      ((uri, integrity) => this.fetchWithIntegrity(uri, integrity));

    // Data may be undefined
    const data = await fetcher(vct, integrity);
    if (!data) return undefined;

    const validated = TypeMetadataFormatSchema.safeParse(data);
    if (!validated.success) {
      throw new SDJWTException(
        `Invalid VCT type metadata for vct '${vct}':\n${z.prettifyError(validated.error)}`,
      );
    }

    return validated.data;
  }

  /**
   * Verifies the status of the SD-JWT-VC.
   * @param result
   * @param options
   */
  private async verifyStatus(
    result: VerificationResult,
    options?: VerifierOptions,
  ): Promise<void> {
    if (result.payload.status) {
      //checks if a status field is present in the payload based on https://www.ietf.org/archive/id/draft-ietf-oauth-status-list-02.html
      if (result.payload.status.status_list) {
        // fetch the status list from the uri
        const fetcher: StatusListFetcher =
          this.userConfig.statusListFetcher ??
          this.statusListFetcher.bind(this);
        // fetch the status list from the uri
        const statusListJWT = await fetcher(
          result.payload.status.status_list.uri,
        );

        const slJWT = Jwt.fromEncode<
          StatusListJWTHeaderParameters,
          StatusListJWTPayload
        >(statusListJWT);
        // check if the status list has a valid signature. The presence of the verifier is checked in the parent class.
        await slJWT
          .verify(
            this.userConfig.statusVerifier ??
              (this.userConfig.verifier as Verifier),
            options,
          )
          .catch((err: SLException) => {
            throw new SLException(
              `Status List JWT verification failed: ${err.message}`,
              err.details,
            );
          });

        // get the status list from the status list JWT
        const statusList = getListFromStatusListJWT(statusListJWT);
        const status = statusList.getStatus(
          result.payload.status.status_list.idx,
        );

        // validate the status
        const statusValidator: StatusValidator =
          this.userConfig.statusValidator ?? this.statusValidator.bind(this);
        await statusValidator(status);
      }
    }
  }
}

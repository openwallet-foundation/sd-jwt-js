import { Jwt, SDJwtInstance } from '@sd-jwt/core';
import type { DisclosureFrame, Hasher, Verifier } from '@sd-jwt/types';
import { SDJWTException } from '@sd-jwt/utils';
import type { SdJwtVcPayload } from './sd-jwt-vc-payload';
import type {
  SDJWTVCConfig,
  StatusListFetcher,
  StatusValidator,
} from './sd-jwt-vc-config';
import {
  type StatusListJWTPayload,
  getListFromStatusListJWT,
  type StatusListJWTHeaderParameters,
} from '@sd-jwt/jwt-status-list';
import type { TypeMetadataFormat } from './sd-jwt-vc-type-metadata-format';
import Ajv, { type SchemaObject } from 'ajv';
import type { VerificationResult } from './verification-result';
import addFormats from 'ajv-formats';
import type { VcTFetcher } from './sd-jwt-vc-vct';

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
    //validate disclosureFrame according to https://www.ietf.org/archive/id/draft-ietf-oauth-sd-jwt-vc-03.html#section-3.2.2.2
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
   */
  async verify(
    encodedSDJwt: string,
    requiredClaimKeys?: string[],
    requireKeyBindings?: boolean,
  ) {
    // Call the parent class's verify method
    const result: VerificationResult = await super
      .verify(encodedSDJwt, requiredClaimKeys, requireKeyBindings)
      .then((res) => {
        return {
          payload: res.payload as SdJwtVcPayload,
          header: res.header,
          kb: res.kb,
        };
      });

    await this.verifyStatus(result);
    if (this.userConfig.loadTypeMetadataFormat) {
      await this.verifyVct(result);
    }
    return result;
  }

  /**
   * Default function to fetch the VCT from the uri. We assume that the vct is a URL that is used to fetch the VCT.
   * @param uri
   * @returns
   */
  private async vctFetcher(
    uri: string,
    integrity?: string,
  ): Promise<TypeMetadataFormat> {
    // modify the uri based on https://www.ietf.org/archive/id/draft-ietf-oauth-sd-jwt-vc-04.html#section-6.3.1
    const elements = uri.split('/');
    //insert a new element on the thrid position, but not replace it
    elements.splice(3, 0, '.well-known/vct');
    const url = elements.join('/');
    return this.fetch<TypeMetadataFormat>(url, integrity);
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
    if (integrity) {
      // validate the integrity of the response according to https://www.w3.org/TR/SRI/
      const arrayBuffer = await response.arrayBuffer();
      const alg = integrity.split('-')[0];
      //TODO: error handling when a hasher is passed that is not supporting the required algorithm acording to the spec
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
  }

  /**
   * Fetches the content from the url with a timeout of 10 seconds.
   * @param url
   * @returns
   */
  private async fetch<T>(url: string, integrity?: string) {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 10000);
    try {
      const response = await fetch(url, {
        signal: controller.signal,
      });
      if (!response.ok) {
        throw new Error(await response.text());
      }
      await this.validateIntegrity(response.clone(), url, integrity);
      return response.json() as Promise<T>;
    } finally {
      clearTimeout(timeoutId);
    }
  }

  /**
   * Loads the schema either from the object or as fallback from the uri.
   * @param typeMetadataFormat
   * @returns
   */
  private async loadSchema(typeMetadataFormat: TypeMetadataFormat) {
    //if schema is present, return it
    if (typeMetadataFormat.schema) return typeMetadataFormat.schema;
    if (typeMetadataFormat.schema_uri) {
      const schema = await this.fetch<SchemaObject>(
        typeMetadataFormat.schema_uri,
        typeMetadataFormat['schema_uri#Integrity'],
      );
      return schema;
    }
    throw new Error('No schema or schema_uri found');
  }

  /**
   * Verifies the VCT of the SD-JWT-VC. Returns the type metadata format. If the schema does not match, an error is thrown. If it matches, it will return the type metadata format.
   * @param result
   * @returns
   */
  private async verifyVct(
    result: VerificationResult,
  ): Promise<TypeMetadataFormat | undefined> {
    const fetcher: VcTFetcher =
      this.userConfig.vctFetcher ?? this.vctFetcher.bind(this);
    const typeMetadataFormat = await fetcher(
      result.payload.vct,
      result.payload['vct#Integrity'],
    );

    if (typeMetadataFormat.extends) {
      // implement based on https://www.ietf.org/archive/id/draft-ietf-oauth-sd-jwt-vc-04.html#name-extending-type-metadata
      //TODO: needs to be implemented. Unclear at this point which values will overwrite the values from the extended type metadata format
    }

    //init the json schema validator, load referenced schemas on demand
    const schema = await this.loadSchema(typeMetadataFormat);
    const loadedSchemas = new Set<string>();
    // init the json schema validator
    const ajv = new Ajv({
      loadSchema: async (uri: string) => {
        if (loadedSchemas.has(uri)) {
          return {};
        }
        const response = await fetch(uri);
        if (!response.ok) {
          throw new Error(
            `Error fetching schema: ${
              response.status
            } ${await response.text()}`,
          );
        }
        loadedSchemas.add(uri);
        return response.json();
      },
    });
    addFormats(ajv);
    const validate = await ajv.compileAsync(schema);
    const valid = validate(result.payload);

    if (!valid) {
      throw new SDJWTException(
        `Payload does not match the schema: ${JSON.stringify(validate.errors)}`,
      );
    }

    return typeMetadataFormat;
  }

  /**
   * Verifies the status of the SD-JWT-VC.
   * @param result
   */
  private async verifyStatus(result: VerificationResult): Promise<void> {
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
        await slJWT.verify(this.userConfig.verifier as Verifier);

        //check if the status list is expired
        if (
          slJWT.payload?.exp &&
          (slJWT.payload.exp as number) < Date.now() / 1000
        ) {
          throw new SDJWTException('Status list is expired');
        }

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

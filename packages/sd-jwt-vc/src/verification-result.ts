import type { kbHeader, kbPayload } from '@sd-jwt/types';
import type { SdJwtVcPayload } from './sd-jwt-vc-payload';
import type { TypeMetadataFormat } from './sd-jwt-vc-type-metadata-format';

export type VerificationResult = {
  payload: SdJwtVcPayload;
  header: Record<string, unknown> | undefined;
  kb:
    | {
        payload: kbPayload;
        header: kbHeader;
      }
    | undefined;
  typeMetadataFormat?: TypeMetadataFormat;
};

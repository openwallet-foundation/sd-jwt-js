import type { JwtPayload } from '@sd-jwt/types';
import { base64urlDecode } from '@sd-jwt/utils';
import { StatusList } from './status-list';
import { StatusListException } from './status-list-exception';
import type {
  JWTwithStatusListPayload,
  StatusListEntry,
  StatusListJWTHeaderParameters,
  StatusListJWTPayload,
} from './types';

/**
 * Decode a JWT and return the payload.
 * @param jwt JWT token in compact JWS serialization.
 * @returns Payload of the JWT.
 */
function decodeJwt<T>(jwt: string): T {
  const parts = jwt.split('.');
  return JSON.parse(base64urlDecode(parts[1]));
}

/**
 * Adds the status list to the payload and header of a JWT.
 * @param list
 * @param payload
 * @param header
 * @returns The header and payload with the status list added.
 */
export function createHeaderAndPayload(
  list: StatusList,
  payload: JwtPayload,
  header: StatusListJWTHeaderParameters,
) {
  // validate if the required fieds are present based on https://www.ietf.org/archive/id/draft-ietf-oauth-status-list-02.html#section-5.1

  if (!payload.iss) {
    throw new StatusListException('iss field is required');
  }
  if (!payload.sub) {
    throw new StatusListException('sub field is required');
  }
  if (!payload.iat) {
    throw new StatusListException('iat field is required');
  }
  //exp and tll are optional. We will not validate the business logic of the values like exp > iat etc.

  header.typ = 'statuslist+jwt';
  payload.status_list = {
    bits: list.getBitsPerStatus(),
    lst: list.compressStatusList(),
  };
  return { header, payload };
}

/**
 * Get the status list from a JWT, but do not verify the signature.
 * @param jwt
 * @returns
 */
export function getListFromStatusListJWT(jwt: string): StatusList {
  const payload = decodeJwt<StatusListJWTPayload>(jwt);
  const statusList = payload.status_list;
  return StatusList.decompressStatusList(statusList.lst, statusList.bits);
}

/**
 * Get the status list entry from a JWT, but do not verify the signature.
 * @param jwt
 * @returns
 */
export function getStatusListFromJWT(jwt: string): StatusListEntry {
  const payload = decodeJwt<JWTwithStatusListPayload>(jwt);
  return payload.status.status_list;
}

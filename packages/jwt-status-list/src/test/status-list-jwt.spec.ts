import {
  createHeaderAndPayload,
  getListFromStatusListJWT,
  getStatusListFromJWT,
} from '../status-list-jwt';
import type {
  StatusListJWTHeaderParameters,
  JWTwithStatusListPayload,
} from '../types';
import { StatusList } from '../status-list';
import { jwtVerify, type KeyLike, SignJWT } from 'jose';
import { beforeAll, describe, expect, it } from 'vitest';
import { generateKeyPairSync } from 'node:crypto';
import type { JwtPayload } from '@sd-jwt/types';

describe('JWTStatusList', () => {
  let publicKey: KeyLike;
  let privateKey: KeyLike;

  const header: StatusListJWTHeaderParameters = {
    alg: 'ES256',
    typ: 'statuslist+jwt',
  };

  beforeAll(() => {
    // Generate a key pair for testing
    const keyPair = generateKeyPairSync('ec', {
      namedCurve: 'P-256',
    });
    publicKey = keyPair.publicKey;
    privateKey = keyPair.privateKey;
  });

  it('should create a JWT with a status list', async () => {
    const statusList = new StatusList([1, 0, 1, 1, 1], 1);
    const iss = 'https://example.com';
    const payload: JwtPayload = {
      iss,
      sub: `${iss}/statuslist/1`,
      iat: Math.floor(Date.now() / 1000),
    };

    const values = createHeaderAndPayload(statusList, payload, header);

    const jwt = await new SignJWT(values.payload)
      .setProtectedHeader(values.header)
      .sign(privateKey);
    // Verify the signed JWT with the public key
    const verified = await jwtVerify(jwt, publicKey);
    expect(verified.payload.status_list).toEqual({
      bits: statusList.getBitsPerStatus(),
      lst: statusList.compressStatusList(),
    });
    expect(verified.protectedHeader.typ).toBe('statuslist+jwt');
  });

  it('should get the status list from a JWT without verifying the signature', async () => {
    const list = [1, 0, 1, 0, 1];
    const statusList = new StatusList(list, 1);
    const iss = 'https://example.com';
    const payload: JwtPayload = {
      iss,
      sub: `${iss}/statuslist/1`,
      iat: Math.floor(Date.now() / 1000),
    };

    const values = createHeaderAndPayload(statusList, payload, header);

    const jwt = await new SignJWT(values.payload)
      .setProtectedHeader(values.header)
      .sign(privateKey);

    const extractedList = getListFromStatusListJWT(jwt);
    for (let i = 0; i < list.length; i++) {
      expect(extractedList.getStatus(i)).toBe(list[i]);
    }
  });

  it('should throw an error if the JWT is invalid', async () => {
    const list = [1, 0, 1, 0, 1];
    const statusList = new StatusList(list, 2);
    const iss = 'https://example.com';
    let payload: JwtPayload = {
      sub: `${iss}/statuslist/1`,
      iat: Math.floor(Date.now() / 1000),
    };
    expect(() => {
      createHeaderAndPayload(statusList, payload as JwtPayload, header);
    }).toThrow('iss field is required');

    payload = {
      iss,
      iat: Math.floor(Date.now() / 1000),
    };
    expect(() => createHeaderAndPayload(statusList, payload, header)).toThrow(
      'sub field is required',
    );

    payload = {
      iss,
      sub: `${iss}/statuslist/1`,
    };
    expect(() => createHeaderAndPayload(statusList, payload, header)).toThrow(
      'iat field is required',
    );
  });

  it('should get the status entry from a JWT', async () => {
    const payload: JWTwithStatusListPayload = {
      iss: 'https://example.com',
      sub: 'https://example.com/status/1',
      iat: Math.floor(Date.now() / 1000),
      status: {
        status_list: {
          idx: 0,
          uri: 'https://example.com/status/1',
        },
      },
    };
    const jwt = await new SignJWT(payload)
      .setProtectedHeader({ alg: 'ES256' })
      .sign(privateKey);
    const reference = getStatusListFromJWT(jwt);
    expect(reference).toEqual(payload.status.status_list);
  });
});

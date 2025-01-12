import { describe, expect, test } from 'vitest';
import { digest } from '@sd-jwt/crypto-nodejs';
import {
  type SerializedDisclosure,
  present,
  presentSync,
  presentableKeys,
  presentableKeysSync,
  selectDisclosures,
  transformPresentationFrame,
} from '../index';
import { decodeSdJwt, decodeSdJwtSync } from '@sd-jwt/decode';
import type { PresentationFrame } from '@sd-jwt/types';

describe('Present tests', () => {
  test('presentableKeys', async () => {
    const sdjwt =
      'eyJ0eXAiOiJzZC1qd3QiLCJhbGciOiJFZERTQSJ9.eyJ0ZXN0Ijp7Il9zZCI6WyJqVEszMHNleDZhYV9kUk1KSWZDR056Q0FwbVB5MzRRNjNBa3QzS3hhSktzIl19LCJfc2QiOlsiME9nMi1ReG95eW1UOGNnVzZZUjVSSFpQLUJuR2tHUi1NM2otLV92RWlzSSIsIkcwZ3lHNnExVFMyUlQxMkZ3X2RRRDVVcjlZc1AwZlVWOXVtQWdGMC1jQ1EiXSwiX3NkX2FsZyI6InNoYS0yNTYifQ.ggEyE4SeDO2Hu3tol3VLmi7NQj56yKzKQDaafocgkLrUBdivghohtzrfcbrMN7CRufJ_Cnh0EL54kymXLGTdDQ~WyIwNGU0MjAzOWU4ZWFiOWRjIiwiYSIsIjEiXQ~WyIwOGE1Yjc5MjMyYjAzYzBhIiwiMSJd~WyJiNWE2YjUzZGQwYTFmMGIwIiwienp6IiwieHh4Il0~WyIxYzdmOTE4ZTE0MjA2NzZiIiwiZm9vIiwiYmFyIl0~WyJmZjYxYzQ5ZGU2NjFiYzMxIiwiYXJyIixbeyIuLi4iOiJTSG96VW5KNUpkd0ZtTjVCbXB5dXZCWGZfZWRjckVvcExPYThTVlBFUmg0In0sIjIiLHsiX3NkIjpbIkpuODNhZkp0OGx4NG1FMzZpRkZyS2U2R2VnN0dlVUQ4Z3UwdVo3NnRZcW8iXX1dXQ~';
    const decodedSdJwt = await decodeSdJwt(sdjwt, digest);
    const keys = await presentableKeys(
      decodedSdJwt.jwt.payload,
      decodedSdJwt.disclosures,
      digest,
    );
    expect(keys).toStrictEqual(['arr', 'arr.0', 'arr.2.a', 'foo', 'test.zzz']);
  });

  test('presentableKeys sync', () => {
    const sdjwt =
      'eyJ0eXAiOiJzZC1qd3QiLCJhbGciOiJFZERTQSJ9.eyJ0ZXN0Ijp7Il9zZCI6WyJqVEszMHNleDZhYV9kUk1KSWZDR056Q0FwbVB5MzRRNjNBa3QzS3hhSktzIl19LCJfc2QiOlsiME9nMi1ReG95eW1UOGNnVzZZUjVSSFpQLUJuR2tHUi1NM2otLV92RWlzSSIsIkcwZ3lHNnExVFMyUlQxMkZ3X2RRRDVVcjlZc1AwZlVWOXVtQWdGMC1jQ1EiXSwiX3NkX2FsZyI6InNoYS0yNTYifQ.ggEyE4SeDO2Hu3tol3VLmi7NQj56yKzKQDaafocgkLrUBdivghohtzrfcbrMN7CRufJ_Cnh0EL54kymXLGTdDQ~WyIwNGU0MjAzOWU4ZWFiOWRjIiwiYSIsIjEiXQ~WyIwOGE1Yjc5MjMyYjAzYzBhIiwiMSJd~WyJiNWE2YjUzZGQwYTFmMGIwIiwienp6IiwieHh4Il0~WyIxYzdmOTE4ZTE0MjA2NzZiIiwiZm9vIiwiYmFyIl0~WyJmZjYxYzQ5ZGU2NjFiYzMxIiwiYXJyIixbeyIuLi4iOiJTSG96VW5KNUpkd0ZtTjVCbXB5dXZCWGZfZWRjckVvcExPYThTVlBFUmg0In0sIjIiLHsiX3NkIjpbIkpuODNhZkp0OGx4NG1FMzZpRkZyS2U2R2VnN0dlVUQ4Z3UwdVo3NnRZcW8iXX1dXQ~';
    const decodedSdJwt = decodeSdJwtSync(sdjwt, digest);
    const keys = presentableKeysSync(
      decodedSdJwt.jwt.payload,
      decodedSdJwt.disclosures,
      digest,
    );
    expect(keys).toStrictEqual(['arr', 'arr.0', 'arr.2.a', 'foo', 'test.zzz']);
  });

  test('present', async () => {
    const sdjwt =
      'eyJ0eXAiOiJzZC1qd3QiLCJhbGciOiJFZERTQSJ9.eyJ0ZXN0Ijp7Il9zZCI6WyJqVEszMHNleDZhYV9kUk1KSWZDR056Q0FwbVB5MzRRNjNBa3QzS3hhSktzIl19LCJfc2QiOlsiME9nMi1ReG95eW1UOGNnVzZZUjVSSFpQLUJuR2tHUi1NM2otLV92RWlzSSIsIkcwZ3lHNnExVFMyUlQxMkZ3X2RRRDVVcjlZc1AwZlVWOXVtQWdGMC1jQ1EiXSwiX3NkX2FsZyI6InNoYS0yNTYifQ.ggEyE4SeDO2Hu3tol3VLmi7NQj56yKzKQDaafocgkLrUBdivghohtzrfcbrMN7CRufJ_Cnh0EL54kymXLGTdDQ~WyIwNGU0MjAzOWU4ZWFiOWRjIiwiYSIsIjEiXQ~WyIwOGE1Yjc5MjMyYjAzYzBhIiwiMSJd~WyJiNWE2YjUzZGQwYTFmMGIwIiwienp6IiwieHh4Il0~WyIxYzdmOTE4ZTE0MjA2NzZiIiwiZm9vIiwiYmFyIl0~WyJmZjYxYzQ5ZGU2NjFiYzMxIiwiYXJyIixbeyIuLi4iOiJTSG96VW5KNUpkd0ZtTjVCbXB5dXZCWGZfZWRjckVvcExPYThTVlBFUmg0In0sIjIiLHsiX3NkIjpbIkpuODNhZkp0OGx4NG1FMzZpRkZyS2U2R2VnN0dlVUQ4Z3UwdVo3NnRZcW8iXX1dXQ~';
    const presentedSdJwt = await present(
      sdjwt,
      {
        foo: true,
        arr: {
          0: true,
        },
        test: {
          zzz: true,
        },
      },
      digest,
    );
    expect(presentedSdJwt).toStrictEqual(
      'eyJ0eXAiOiJzZC1qd3QiLCJhbGciOiJFZERTQSJ9.eyJ0ZXN0Ijp7Il9zZCI6WyJqVEszMHNleDZhYV9kUk1KSWZDR056Q0FwbVB5MzRRNjNBa3QzS3hhSktzIl19LCJfc2QiOlsiME9nMi1ReG95eW1UOGNnVzZZUjVSSFpQLUJuR2tHUi1NM2otLV92RWlzSSIsIkcwZ3lHNnExVFMyUlQxMkZ3X2RRRDVVcjlZc1AwZlVWOXVtQWdGMC1jQ1EiXSwiX3NkX2FsZyI6InNoYS0yNTYifQ.ggEyE4SeDO2Hu3tol3VLmi7NQj56yKzKQDaafocgkLrUBdivghohtzrfcbrMN7CRufJ_Cnh0EL54kymXLGTdDQ~WyIxYzdmOTE4ZTE0MjA2NzZiIiwiZm9vIiwiYmFyIl0~WyJmZjYxYzQ5ZGU2NjFiYzMxIiwiYXJyIixbeyIuLi4iOiJTSG96VW5KNUpkd0ZtTjVCbXB5dXZCWGZfZWRjckVvcExPYThTVlBFUmg0In0sIjIiLHsiX3NkIjpbIkpuODNhZkp0OGx4NG1FMzZpRkZyS2U2R2VnN0dlVUQ4Z3UwdVo3NnRZcW8iXX1dXQ~WyIwOGE1Yjc5MjMyYjAzYzBhIiwiMSJd~WyJiNWE2YjUzZGQwYTFmMGIwIiwienp6IiwieHh4Il0~',
    );
  });

  test('present sync', () => {
    const sdjwt =
      'eyJ0eXAiOiJzZC1qd3QiLCJhbGciOiJFZERTQSJ9.eyJ0ZXN0Ijp7Il9zZCI6WyJqVEszMHNleDZhYV9kUk1KSWZDR056Q0FwbVB5MzRRNjNBa3QzS3hhSktzIl19LCJfc2QiOlsiME9nMi1ReG95eW1UOGNnVzZZUjVSSFpQLUJuR2tHUi1NM2otLV92RWlzSSIsIkcwZ3lHNnExVFMyUlQxMkZ3X2RRRDVVcjlZc1AwZlVWOXVtQWdGMC1jQ1EiXSwiX3NkX2FsZyI6InNoYS0yNTYifQ.ggEyE4SeDO2Hu3tol3VLmi7NQj56yKzKQDaafocgkLrUBdivghohtzrfcbrMN7CRufJ_Cnh0EL54kymXLGTdDQ~WyIwNGU0MjAzOWU4ZWFiOWRjIiwiYSIsIjEiXQ~WyIwOGE1Yjc5MjMyYjAzYzBhIiwiMSJd~WyJiNWE2YjUzZGQwYTFmMGIwIiwienp6IiwieHh4Il0~WyIxYzdmOTE4ZTE0MjA2NzZiIiwiZm9vIiwiYmFyIl0~WyJmZjYxYzQ5ZGU2NjFiYzMxIiwiYXJyIixbeyIuLi4iOiJTSG96VW5KNUpkd0ZtTjVCbXB5dXZCWGZfZWRjckVvcExPYThTVlBFUmg0In0sIjIiLHsiX3NkIjpbIkpuODNhZkp0OGx4NG1FMzZpRkZyS2U2R2VnN0dlVUQ4Z3UwdVo3NnRZcW8iXX1dXQ~';
    const presentedSdJwt = presentSync(
      sdjwt,
      {
        foo: true,
        arr: {
          0: true,
        },
        test: {
          zzz: true,
        },
      },
      digest,
    );
    expect(presentedSdJwt).toStrictEqual(
      'eyJ0eXAiOiJzZC1qd3QiLCJhbGciOiJFZERTQSJ9.eyJ0ZXN0Ijp7Il9zZCI6WyJqVEszMHNleDZhYV9kUk1KSWZDR056Q0FwbVB5MzRRNjNBa3QzS3hhSktzIl19LCJfc2QiOlsiME9nMi1ReG95eW1UOGNnVzZZUjVSSFpQLUJuR2tHUi1NM2otLV92RWlzSSIsIkcwZ3lHNnExVFMyUlQxMkZ3X2RRRDVVcjlZc1AwZlVWOXVtQWdGMC1jQ1EiXSwiX3NkX2FsZyI6InNoYS0yNTYifQ.ggEyE4SeDO2Hu3tol3VLmi7NQj56yKzKQDaafocgkLrUBdivghohtzrfcbrMN7CRufJ_Cnh0EL54kymXLGTdDQ~WyIxYzdmOTE4ZTE0MjA2NzZiIiwiZm9vIiwiYmFyIl0~WyJmZjYxYzQ5ZGU2NjFiYzMxIiwiYXJyIixbeyIuLi4iOiJTSG96VW5KNUpkd0ZtTjVCbXB5dXZCWGZfZWRjckVvcExPYThTVlBFUmg0In0sIjIiLHsiX3NkIjpbIkpuODNhZkp0OGx4NG1FMzZpRkZyS2U2R2VnN0dlVUQ4Z3UwdVo3NnRZcW8iXX1dXQ~WyIwOGE1Yjc5MjMyYjAzYzBhIiwiMSJd~WyJiNWE2YjUzZGQwYTFmMGIwIiwienp6IiwieHh4Il0~',
    );
  });

  test('transform an object for a presentation to a list', () => {
    const claims = {
      firstname: 'John',
      lastname: 'Doe',
      ssn: '123-45-6789',
      id: '1234',
      data: {
        firstname: 'John',
        lastname: 'Doe',
        ssn: '123-45-6789',
        list: [{ r: 'd' }, 'b', 'c'],
        list2: ['1', '2', '3'],
        list3: ['1', null, 2],
      },
      data2: {
        hi: 'bye',
      },
    };

    const presentFrame: PresentationFrame<typeof claims> = {
      firstname: true,
      data: {
        firstname: true,
        list: {
          1: true,
          0: {
            r: true,
          },
        },
        list2: {
          1: true,
        },
        list3: true,
      },
      data2: true,
    };

    const list = transformPresentationFrame<typeof claims>(presentFrame);
    expect(list).toStrictEqual([
      'firstname',
      'data',
      'data.firstname',
      'data.list',
      'data.list.0',
      'data.list.0.r',
      'data.list.1',
      'data.list2',
      'data.list2.1',
      'data.list3',
      'data2',
    ]);
  });

  test('transform an object for a presentation to a list, but with faulty inputs', () => {
    const claims = {
      name: 'John',
      address: {
        city: 'New York',
        street: '5th Avenue',
      },
    };

    const obj: PresentationFrame<typeof claims> = {
      name: false,
      address: {
        city: true,
        street: true,
      },
    };
    const list = transformPresentationFrame<typeof claims>(obj);
    expect(list).toStrictEqual(['address', 'address.city', 'address.street']);
  });

  test('select disclosures', () => {
    const payload = {
      lastname: 'Doe',
      _sd: [
        'COnqXH7wGBFGR1ao12sDwTfu84Zs7cq92CZIg8ulIuU',
        'RrOc4ZfBVyD6iNlMbtmdokZOti322mOXfvIOBKvpuc4',
        'aXqInKwHoE1l8OM1VNUQDqTPeNUG1cMJVwVbxZJpP14',
      ],
      _sd_alg: 'sha-256',
    };

    const presentationFrame = {
      firstname: true,
      //ssn: true,
      id: true,
    };

    const disclosures: SerializedDisclosure[] = [
      {
        digest: 'COnqXH7wGBFGR1ao12sDwTfu84Zs7cq92CZIg8ulIuU',
        encoded: 'WyJiMDQ3NjBiOTgxMDgyM2ZhIiwiZmlyc3RuYW1lIiwiSm9obiJd',
        salt: 'b04760b9810823fa',
        key: 'firstname',
        value: 'John',
      },
      {
        digest: 'RrOc4ZfBVyD6iNlMbtmdokZOti322mOXfvIOBKvpuc4',
        encoded: 'WyJjNTQwZWE4YjJhOTNmZDE1Iiwic3NuIiwiMTIzLTQ1LTY3ODkiXQ',
        salt: 'c540ea8b2a93fd15',
        key: 'ssn',
        value: '123-45-6789',
      },
      {
        digest: 'aXqInKwHoE1l8OM1VNUQDqTPeNUG1cMJVwVbxZJpP14',
        encoded: 'WyI5N2YwNTVkZTk0NGFmNzI5IiwiaWQiLCIxMjM0Il0',
        salt: '97f055de944af729',
        key: 'id',
        value: '1234',
      },
    ];

    const selected = selectDisclosures(payload, disclosures, presentationFrame);
    expect(selected).toStrictEqual([
      {
        digest: 'COnqXH7wGBFGR1ao12sDwTfu84Zs7cq92CZIg8ulIuU',
        encoded: 'WyJiMDQ3NjBiOTgxMDgyM2ZhIiwiZmlyc3RuYW1lIiwiSm9obiJd',
        salt: 'b04760b9810823fa',
        key: 'firstname',
        value: 'John',
      },
      {
        digest: 'aXqInKwHoE1l8OM1VNUQDqTPeNUG1cMJVwVbxZJpP14',
        encoded: 'WyI5N2YwNTVkZTk0NGFmNzI5IiwiaWQiLCIxMjM0Il0',
        salt: '97f055de944af729',
        key: 'id',
        value: '1234',
      },
    ]);
  });

  test('select disclosures no input', () => {
    const selected = selectDisclosures({}, [], {});
    expect(selected).toStrictEqual([]);
  });

  test('select disclosures noting return', () => {
    const payload = {
      lastname: 'Doe',
      _sd: [
        'COnqXH7wGBFGR1ao12sDwTfu84Zs7cq92CZIg8ulIuU',
        'RrOc4ZfBVyD6iNlMbtmdokZOti322mOXfvIOBKvpuc4',
        'aXqInKwHoE1l8OM1VNUQDqTPeNUG1cMJVwVbxZJpP14',
      ],
      _sd_alg: 'sha-256',
    };

    const presentationFrame = {};

    const disclosures: SerializedDisclosure[] = [
      {
        digest: 'COnqXH7wGBFGR1ao12sDwTfu84Zs7cq92CZIg8ulIuU',
        encoded: 'WyJiMDQ3NjBiOTgxMDgyM2ZhIiwiZmlyc3RuYW1lIiwiSm9obiJd',
        salt: 'b04760b9810823fa',
        key: 'firstname',
        value: 'John',
      },
      {
        digest: 'RrOc4ZfBVyD6iNlMbtmdokZOti322mOXfvIOBKvpuc4',
        encoded: 'WyJjNTQwZWE4YjJhOTNmZDE1Iiwic3NuIiwiMTIzLTQ1LTY3ODkiXQ',
        salt: 'c540ea8b2a93fd15',
        key: 'ssn',
        value: '123-45-6789',
      },
      {
        digest: 'aXqInKwHoE1l8OM1VNUQDqTPeNUG1cMJVwVbxZJpP14',
        encoded: 'WyI5N2YwNTVkZTk0NGFmNzI5IiwiaWQiLCIxMjM0Il0',
        salt: '97f055de944af729',
        key: 'id',
        value: '1234',
      },
    ];
    const selected = selectDisclosures(payload, disclosures, presentationFrame);
    expect(selected).toStrictEqual([]);
  });

  test('expect missing digest', () => {
    const payload = {
      lastname: 'Doe',
      _sd: [
        'COnqXH7wGBFGR1ao12sDwTfu84Zs7cq92CZIg8ulIuU',
        'RrOc4ZfBVyD6iNlMbtmdokZOti322mOXfvIOBKvpuc4',
        'aXqInKwHoE1l8OM1VNUQDqTPeNUG1cMJVwVbxZJpP14',
      ],
      _sd_alg: 'sha-256',
    };

    const presentationFrame = {
      firstname: true,
      //ssn: true,
      id: true,
    };

    const disclosures: SerializedDisclosure[] = [
      //@ts-ignore
      {
        encoded: 'WyJiMDQ3NjBiOTgxMDgyM2ZhIiwiZmlyc3RuYW1lIiwiSm9obiJd',
        salt: 'b04760b9810823fa',
        key: 'firstname',
        value: 'John',
      },
      {
        digest: 'RrOc4ZfBVyD6iNlMbtmdokZOti322mOXfvIOBKvpuc4',
        encoded: 'WyJjNTQwZWE4YjJhOTNmZDE1Iiwic3NuIiwiMTIzLTQ1LTY3ODkiXQ',
        salt: 'c540ea8b2a93fd15',
        key: 'ssn',
        value: '123-45-6789',
      },
      {
        digest: 'aXqInKwHoE1l8OM1VNUQDqTPeNUG1cMJVwVbxZJpP14',
        encoded: 'WyI5N2YwNTVkZTk0NGFmNzI5IiwiaWQiLCIxMjM0Il0',
        salt: '97f055de944af729',
        key: 'id',
        value: '1234',
      },
    ];

    expect(() =>
      selectDisclosures(payload, disclosures, presentationFrame),
    ).toThrowError('Implementation error: _digest is not defined');
  });
});

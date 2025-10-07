import { digest } from '@sd-jwt/crypto-nodejs';
import { decodeSdJwt, getClaims } from '@sd-jwt/decode';
import { present, presentableKeys } from '@sd-jwt/present';

(async () => {
  const sdjwt =
    'eyJ0eXAiOiJzZC1qd3QiLCJhbGciOiJFZERTQSJ9.eyJ0ZXN0Ijp7Il9zZCI6WyJqVEszMHNleDZhYV9kUk1KSWZDR056Q0FwbVB5MzRRNjNBa3QzS3hhSktzIl19LCJfc2QiOlsiME9nMi1ReG95eW1UOGNnVzZZUjVSSFpQLUJuR2tHUi1NM2otLV92RWlzSSIsIkcwZ3lHNnExVFMyUlQxMkZ3X2RRRDVVcjlZc1AwZlVWOXVtQWdGMC1jQ1EiXSwiX3NkX2FsZyI6InNoYS0yNTYifQ.ggEyE4SeDO2Hu3tol3VLmi7NQj56yKzKQDaafocgkLrUBdivghohtzrfcbrMN7CRufJ_Cnh0EL54kymXLGTdDQ~WyIwNGU0MjAzOWU4ZWFiOWRjIiwiYSIsIjEiXQ~WyIwOGE1Yjc5MjMyYjAzYzBhIiwiMSJd~WyJiNWE2YjUzZGQwYTFmMGIwIiwienp6IiwieHh4Il0~WyIxYzdmOTE4ZTE0MjA2NzZiIiwiZm9vIiwiYmFyIl0~WyJmZjYxYzQ5ZGU2NjFiYzMxIiwiYXJyIixbeyIuLi4iOiJTSG96VW5KNUpkd0ZtTjVCbXB5dXZCWGZfZWRjckVvcExPYThTVlBFUmg0In0sIjIiLHsiX3NkIjpbIkpuODNhZkp0OGx4NG1FMzZpRkZyS2U2R2VnN0dlVUQ4Z3UwdVo3NnRZcW8iXX1dXQ~';
  const decodedSdJwt = await decodeSdJwt(sdjwt, digest);
  console.log('The decoded Disclosures are:');
  console.log(JSON.stringify(decodedSdJwt.disclosures, null, 2));
  console.log(
    '================================================================',
  );

  const claims = await getClaims(
    decodedSdJwt.jwt.payload,
    decodedSdJwt.disclosures,
    digest,
  );

  console.log('The claims are:');
  console.log(JSON.stringify(claims, null, 2));

  // You can get presentable keys from the decoded SD JWT
  const keys = await presentableKeys(
    decodedSdJwt.jwt.payload,
    decodedSdJwt.disclosures,
    digest,
  );
  console.log('The presentable keys are:', keys);

  // You can present the SD JWT with the combination of presentable keys
  const presentedSdJwt = await present<{
    foo: string;
    test: { zzz: string };
    arr: (string | { a: string })[];
  }>(
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

  console.log('The presented SD JWT is:', presentedSdJwt);

  console.log(
    '================================================================',
  );

  // If you decoded the presented SD JWT, you can see the presented disclosures
  // It only contains the disclosed keys you presented
  const presentedDecodedSdJwt = await decodeSdJwt(presentedSdJwt, digest);

  console.log('The decoded Disclosures are:');
  console.log(JSON.stringify(presentedDecodedSdJwt.disclosures, null, 2));

  const presentedClaims = await getClaims(
    presentedDecodedSdJwt.jwt.payload,
    presentedDecodedSdJwt.disclosures,
    digest,
  );

  console.log('The presented claims are:');
  console.log(JSON.stringify(presentedClaims, null, 2));
})();

import { Sign } from './sign';
export * from './type';
export * from './constant';
export * from './utils';
import { Present } from './present';
import { JWTVerifier } from './verify';

export const JAdES = {
  Sign,
  Present,
  Verify: JWTVerifier,
};

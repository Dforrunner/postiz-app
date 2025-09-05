import { sign, verify } from 'jsonwebtoken';
import { hashSync, compareSync } from 'bcrypt';
import crypto from 'crypto';

// Validate environment variables at application startup.
const JWT_SECRET = process.env.JWT_SECRET;
const SALT = process.env.SALT; // Change this in production

if (!JWT_SECRET || !SALT) {
  console.error('Critical environment variables JWT_SECRET or SALT are not set.');
  process.exit(1);
}

const ALGORITHM = 'aes-256-gcm' as const;
const IV_LENGTH = 12; // 12 bytes is recommended for GCM mode
const AUTH_TAG_LENGTH = 16; // 16 bytes for GCM
const KEY_LENGTH = 32; // 32 bytes for AES-256

export class AuthService {
  // Key derivation function
  private static getKey = () => {
    return crypto.scryptSync(JWT_SECRET, SALT, KEY_LENGTH) as Uint8Array;
  };

  static hashPassword(password: string) {
    return hashSync(password, 12);
  }

  static comparePassword(password: string, hash: string) {
    return compareSync(password, hash);
  }

  static signJWT(value: object) {
    return sign(value, JWT_SECRET, { expiresIn: '1h' });
  }

  static verifyJWT(token: string){
    return verify(token, JWT_SECRET);
  }

  static fixedEncryption(value: string) {
    const iv = crypto.randomBytes(IV_LENGTH) as Uint8Array;
    const key = this.getKey();
    const cipher = crypto.createCipheriv(ALGORITHM, key, iv, {
      authTagLength: AUTH_TAG_LENGTH,
    });

    let encrypted = cipher.update(value, 'utf8', 'hex');
    encrypted += cipher.final('hex');

    const authTag = cipher.getAuthTag() as Uint8Array;

    // Format: iv:authTag:encryptedData
    return Buffer.concat([iv, authTag]).toString('hex') + ':' + encrypted;
  }

  static fixedDecryption(hash: string): string {
    const parts = hash.split(':');
    if (parts.length !== 2) {
      throw new Error('Invalid encrypted format');
    }

    const ivAndAuthTag = Buffer.from(parts[0], 'hex');
    const iv = ivAndAuthTag.subarray(0, IV_LENGTH) as crypto.BinaryLike;
    const authTag = ivAndAuthTag.subarray(IV_LENGTH) as Uint8Array;
    const encrypted = parts[1];
    const key = this.getKey();

    const decipher = crypto.createDecipheriv(ALGORITHM, key, iv, {
      authTagLength: AUTH_TAG_LENGTH,
    });

    decipher.setAuthTag(authTag);

    let decrypted = decipher.update(encrypted, 'hex', 'utf8');
    decrypted += decipher.final('utf8');

    return decrypted;
  }
}

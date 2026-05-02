// -----------------------------------------------------------------------
// Portable Diffie-Hellman MODP-14 (RFC 3526 group 14, 2048-bit) via
// BouncyCastle. The Windows PAL uses bcrypt.dll; the Linux PAL previously
// threw PlatformNotSupported for all DH groups, breaking PKINIT.
//
// Output byte order matches the Windows BCrypt impl: keys and the agreed
// shared secret are big-endian, padded/truncated to 256 bytes (2048 bits).
// PKInitString2Key consumes the secret in big-endian order per RFC 4556.
// -----------------------------------------------------------------------

using System;
using BcBigInteger = Org.BouncyCastle.Math.BigInteger;
using Org.BouncyCastle.Crypto.Agreement;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using BcSecureRandom = Org.BouncyCastle.Security.SecureRandom;

namespace Kerberos.NET.Crypto
{
    internal sealed class BouncyCastleDiffieHellmanOakleyGroup14 : IKeyAgreement
    {
        private const int KeyLengthBytes = 256; // 2048 bits

        private static readonly BcBigInteger Prime = new BcBigInteger(1, Oakley.Group14.Prime.ToArray());
        private static readonly BcBigInteger Generator = new BcBigInteger(1, Oakley.Group14.Generator.ToArray());
        private static readonly DHParameters Params = new DHParameters(Prime, Generator);

        private readonly DHPrivateKeyParameters privateParams;
        private readonly DHPublicKeyParameters publicParams;
        private DHPublicKeyParameters partnerParams;

        public IExchangeKey PublicKey { get; }

        public IExchangeKey PrivateKey { get; }

        public BouncyCastleDiffieHellmanOakleyGroup14(DiffieHellmanKey importKey = null)
        {
            if (importKey != null && importKey.PrivateComponent.Length > 0)
            {
                var x = new BcBigInteger(1, importKey.PrivateComponent.ToArray());
                this.privateParams = new DHPrivateKeyParameters(x, Params);
                var y = importKey.PublicComponent.Length > 0
                    ? new BcBigInteger(1, importKey.PublicComponent.ToArray())
                    : Generator.ModPow(x, Prime);
                this.publicParams = new DHPublicKeyParameters(y, Params);
            }
            else
            {
                var generator = new DHKeyPairGenerator();
                generator.Init(new DHKeyGenerationParameters(new BcSecureRandom(), Params));
                var pair = generator.GenerateKeyPair();
                this.privateParams = (DHPrivateKeyParameters)pair.Private;
                this.publicParams = (DHPublicKeyParameters)pair.Public;
            }

            byte[] modulusBytes = ToFixedBigEndian(Prime, KeyLengthBytes);
            byte[] generatorBytes = ToFixedBigEndian(Generator, KeyLengthBytes);
            byte[] pubBytes = ToFixedBigEndian(this.publicParams.Y, KeyLengthBytes);
            byte[] privBytes = ToFixedBigEndian(this.privateParams.X, KeyLengthBytes);

            this.PrivateKey = new DiffieHellmanKey
            {
                Type = AsymmetricKeyType.Private,
                Algorithm = KeyAgreementAlgorithm.DiffieHellmanModp14,
                KeyLength = KeyLengthBytes,
                Modulus = modulusBytes,
                Generator = generatorBytes,
                Factor = Oakley.Group14.Factor,
                PublicComponent = pubBytes,
                PrivateComponent = privBytes,
                CacheExpiry = importKey?.CacheExpiry,
            };

            this.PublicKey = new DiffieHellmanKey
            {
                Type = AsymmetricKeyType.Public,
                Algorithm = KeyAgreementAlgorithm.DiffieHellmanModp14,
                KeyLength = KeyLengthBytes,
                Modulus = modulusBytes,
                Generator = generatorBytes,
                Factor = Oakley.Group14.Factor,
                PublicComponent = pubBytes,
                CacheExpiry = importKey?.CacheExpiry,
            };
        }

        public void ImportPartnerKey(IExchangeKey publicKey)
        {
            if (publicKey is not DiffieHellmanKey k)
                throw new ArgumentException("Expected DiffieHellmanKey", nameof(publicKey));
            var y = new BcBigInteger(1, k.PublicComponent.ToArray());
            this.partnerParams = new DHPublicKeyParameters(y, Params);
        }

        public ReadOnlyMemory<byte> GenerateAgreement()
        {
            if (this.partnerParams == null)
                throw new InvalidOperationException("Partner key not imported");
            var agreement = new DHBasicAgreement();
            agreement.Init(this.privateParams);
            BcBigInteger sharedSecret = agreement.CalculateAgreement(this.partnerParams);
            return ToFixedBigEndian(sharedSecret, KeyLengthBytes);
        }

        public void Dispose()
        {
            // No native resources held.
        }

        private static byte[] ToFixedBigEndian(BcBigInteger value, int length)
        {
            byte[] raw = value.ToByteArrayUnsigned();
            if (raw.Length == length) return raw;
            if (raw.Length > length)
                throw new InvalidOperationException("Value exceeds target length");
            byte[] padded = new byte[length];
            Array.Copy(raw, 0, padded, length - raw.Length, raw.Length);
            return padded;
        }
    }
}

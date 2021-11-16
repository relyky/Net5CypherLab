using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;

namespace Net5ConaoleApp.Services
{
    class CryptographyService
    {
        readonly IConfiguration _config;
        readonly ILogger<CryptographyService> _logger;

        public CryptographyService(ILogger<CryptographyService> logger, IConfiguration config)
        {
            _logger = logger;
            _config = config;
        }

        public byte[] EncryptDataOaepSha256(X509Certificate2 cert, byte[] data)
        {
            using (RSA rsa = cert.GetRSAPublicKey())
            {
                return rsa.Encrypt(data, RSAEncryptionPadding.OaepSHA256);
            }
        }

        public byte[] DecryptDataOaepSha256(X509Certificate2 cert, byte[] data)
        {
            // GetRSAPrivateKey returns an object with an independent lifetime, so it should be
            // handled via a using statement.
            using (RSA rsa = cert.GetRSAPrivateKey())
            {
                return rsa.Decrypt(data, RSAEncryptionPadding.OaepSHA256);
            }
        }

        /// <summary>
        /// 用公鑰加密
        /// </summary>
        public byte[] EncryptDataOaepSha1(string thumbprint, object data)
        {
            var cert = FindCertInStore(StoreName.My, StoreLocation.CurrentUser, thumbprint);
            if (cert == null) throw new ApplicationException("目標憑證不存在！");

            var blob = JsonSerializer.SerializeToUtf8Bytes(data, data.GetType());
            using (RSA rsa = cert.GetRSAPublicKey())
            {
                return rsa.Encrypt(blob, RSAEncryptionPadding.OaepSHA1);
            }
        }

        /// <summary>
        /// 用私鑰解密
        /// </summary>
        public T DecryptDataOaepSha1<T>(string thumbprint, byte[] cryptoBlob)
        {
            //## 私密金鑰只能放在【Cert:CurrentUser\My】位置。
            var cert = FindCertInStore(StoreName.My, StoreLocation.CurrentUser, thumbprint);
            if (cert == null) throw new ApplicationException("目標憑證不存在！");

            using (RSA rsa = cert.GetRSAPrivateKey())
            {
                var dataBlob = rsa.Decrypt(cryptoBlob, RSAEncryptionPadding.OaepSHA1);
                var data = JsonSerializer.Deserialize<T>(dataBlob);
                return data;
            }
        }

        public byte[] SignData(string thumbprint, object data)
        {
            var cert = FindCertInStore(StoreName.My, StoreLocation.CurrentUser, thumbprint);
            if (cert == null) throw new ApplicationException("目標憑證不存在！");

            var blob = JsonSerializer.SerializeToUtf8Bytes(data, data.GetType());
            using (RSA rsa = cert.GetRSAPrivateKey())
            {
                return rsa.SignData(blob, HashAlgorithmName.SHA1, RSASignaturePadding.Pss);
            }
        }

        public bool VerifyData(string thumbprint, object data, byte[] signature)
        {
            var cert = FindCertInStore(StoreName.My, StoreLocation.CurrentUser, thumbprint);
            if (cert == null) throw new ApplicationException("目標憑證不存在！");

            var blob = JsonSerializer.SerializeToUtf8Bytes(data, data.GetType());
            using (RSA rsa = cert.GetRSAPrivateKey())
            {
                return rsa.VerifyData(blob, signature, HashAlgorithmName.SHA1, RSASignaturePadding.Pss);
            }
        }

        /// <summary>
        /// 參考：[Using the AesGcm class](https://stackoverflow.com/questions/60889345/using-the-aesgcm-class)
        /// </summary>
        public byte[] EncryptData(string key, object data, string associatedData = null)
        {
            // Get bytes of plaintext string
            byte[] plainBytes = JsonSerializer.SerializeToUtf8Bytes(data, data.GetType());

            // Get parameter sizes
            int nonceSize = AesGcm.NonceByteSizes.MaxSize;
            int tagSize = AesGcm.TagByteSizes.MaxSize;
            int cipherSize = plainBytes.Length;

            // We write everything into one big array for easier encoding
            int encryptedDataLength = 4 + nonceSize + 4 + tagSize + cipherSize;
            Span<byte> encryptedData = encryptedDataLength < 1024
                                     ? stackalloc byte[encryptedDataLength]
                                     : new byte[encryptedDataLength].AsSpan();

            // Copy parameters
            BinaryPrimitives.WriteInt32LittleEndian(encryptedData.Slice(0, 4), nonceSize);
            BinaryPrimitives.WriteInt32LittleEndian(encryptedData.Slice(4 + nonceSize, 4), tagSize);
            var nonce = encryptedData.Slice(4, nonceSize);
            var tag = encryptedData.Slice(4 + nonceSize + 4, tagSize);
            var cipherBytes = encryptedData.Slice(4 + nonceSize + 4 + tagSize, cipherSize);

            // Generate secure nonce
            RandomNumberGenerator.Fill(nonce);

            // key & associatedData 
            byte[] ass = associatedData == null ? null : ASCIIEncoding.ASCII.GetBytes(associatedData);
            using var shaer = SHA256.Create();
            byte[] keyCode = shaer.ComputeHash(ASCIIEncoding.ASCII.GetBytes(key));

            // Encrypt
            using var aes = new AesGcm(keyCode);
            aes.Encrypt(nonce, plainBytes.AsSpan(), cipherBytes, tag, ass);

            // Encode for transmission
            return encryptedData.ToArray();
        }

        /// <summary>
        /// 參考：[Using the AesGcm class](https://stackoverflow.com/questions/60889345/using-the-aesgcm-class)
        /// </summary>
        public T DecryptData<T>(string key, byte[] cipherData, string associatedData = null)
        {
            // Decode
            Span<byte> encryptedData = cipherData.AsSpan();

            // Extract parameter sizes
            int nonceSize = BinaryPrimitives.ReadInt32LittleEndian(encryptedData.Slice(0, 4));
            int tagSize = BinaryPrimitives.ReadInt32LittleEndian(encryptedData.Slice(4 + nonceSize, 4));
            int cipherSize = encryptedData.Length - 4 - nonceSize - 4 - tagSize;

            // Extract parameters
            var nonce = encryptedData.Slice(4, nonceSize);
            var tag = encryptedData.Slice(4 + nonceSize + 4, tagSize);
            var cipherBytes = encryptedData.Slice(4 + nonceSize + 4 + tagSize, cipherSize);

            // key & associatedData 
            byte[] ass = associatedData == null ? null : ASCIIEncoding.ASCII.GetBytes(associatedData);
            using var shaer = SHA256.Create();
            byte[] keyCode = shaer.ComputeHash(ASCIIEncoding.ASCII.GetBytes(key));

            // Decrypt
            Span<byte> plainBytes = cipherSize < 1024
                                  ? stackalloc byte[cipherSize]
                                  : new byte[cipherSize];

            using var aes = new AesGcm(keyCode);
            aes.Decrypt(nonce, cipherBytes, tag, plainBytes, ass);

            // Convert plain bytes back into string
            //return Encoding.UTF8.GetString(plainBytes);
            T data = JsonSerializer.Deserialize<T>(plainBytes);
            return data;
        }

        public Span<byte> ProtectData(string thumbprint, object data, string key, string associatedData = null)
        {
            byte[] signature = SignData(thumbprint, data);
            byte[] cipherData = EncryptData(key, data, associatedData);
            return cipherData.Concat(signature).ToArray().AsSpan();
        }

        public bool UnprotectData<T>(Span<byte> pkg, out T plainData, string thumbprint, string key, string associatedData = null)
        {
            plainData = default;

            try
            {
                byte[] cipherData = pkg.Slice(0, pkg.Length - 256).ToArray();
                byte[] signature = pkg.Slice(pkg.Length - 256).ToArray();

                T decryptData = DecryptData<T>(key, cipherData, associatedData);
                if (VerifyData(thumbprint, decryptData, signature)) 
                {
                    plainData = decryptData;
                    return true;
                }

                return false;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"UnprotectData FAIL! {ex.Message}");
                return false;
            }
        }

        static X509Certificate2 FindCertInStore(StoreName storeName, StoreLocation location, string thumbprint, bool validOnly = true)
        {
            using (X509Store store = new X509Store(storeName, location))
            {
                store.Open(OpenFlags.ReadOnly | OpenFlags.MaxAllowed | OpenFlags.IncludeArchived);
                var result = store.Certificates.Find(X509FindType.FindByThumbprint, thumbprint, validOnly);
                if (result.Count > 0)
                {
                    return result[0];
                };
            }

            //throw new ApplicationException($@"找不到目標憑證[Subject = {subject}]！");
            return null;
        }
    }

    
}

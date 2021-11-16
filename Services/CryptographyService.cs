using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using System;
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

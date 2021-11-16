using Microsoft.Extensions.Configuration;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Net5ConaoleApp.Services;
using System.IO;
using System.Runtime.Serialization;
using System.Runtime.Serialization.Formatters.Binary;
using System.Text.Json;
using System.Security.Cryptography.X509Certificates;

namespace Net5ConaoleApp
{
    class App
    {
        readonly IConfiguration _config;
        readonly CryptographyService _cypher;

        public App(IConfiguration config, CryptographyService cypher)
        {
            _config = config;
            _cypher = cypher;
        }

        /// <summary>
        /// 取代原本 Program.Main() 函式的效用。
        /// </summary>
        public void Run(string[] args)
        {
            Dictionary<string, string> connList = new Dictionary<string, string>();
            connList.Add("ConnDB", "我是連線字串1");
            connList.Add("Conn2DB", "我是連線字串2");
            connList.Add("Conn3DB", "我是連線字串3");
            connList.Add("Conn4DB", "我是連線字串4");
            connList.Add("Conn5DB", "我是連線字串1");
            connList.Add("Conn6DB", "我是連線字串2");
            connList.Add("Conn7DB", "我是連線字串3");
            connList.Add("Conn8DB", "我是連線字串4");
            connList.Add("Conn9B", "我是連線字串1");
            connList.Add("ConnADB", "我是連線字串2");
            connList.Add("ConnBDB", "我是連線字串3");
            connList.Add("ConnCDB", "我是連線字串4");

            string thumbprint = @"6CF5ACB9F5AF03741FF924A8542A0D108F453595";

            //var cryptoBlob = _cypher.EncryptDataOaepSha1(thumbprint, connList);
            //var dataBlob = _cypher.DecryptDataOaepSha1<Dictionary<string,string>>(thumbprint, cryptoBlob);

            var signature = _cypher.SignData(thumbprint, connList);
            bool isValid = _cypher.VerifyData(thumbprint, connList, signature);

            var cipherData = _cypher.EncryptData("show me the money", connList, "是的");
            var plainData = _cypher.DecryptData<Dictionary<string, string>>("show me the money", cipherData, "是的");

            var pkg = _cypher.ProtectData(thumbprint, connList, "show me the money");

            Dictionary<string, string> result;
            bool isOk = _cypher.UnprotectData<Dictionary<string, string>>(pkg, out result, thumbprint, "show me the money");

            Console.WriteLine("Press any key to continue.");
            Console.ReadKey();
        }
    }

}

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

            var cryptoBlob = _cypher.EncryptDataOaepSha1(thumbprint, connList);
            var dataBlob = _cypher.DecryptDataOaepSha1<Dictionary<string,string>>(thumbprint, cryptoBlob);

            var signature = _cypher.SignData(thumbprint, connList);
            bool isValid = _cypher.VerifyData(thumbprint, connList, signature);

            Console.WriteLine("Press any key to continue.");
            Console.ReadKey();
        }
    }

}

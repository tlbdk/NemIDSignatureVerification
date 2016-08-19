using System;
using System.IO;

namespace NemIDSignatureVerification
{
    public class Program
    {
        public static void Main(string[] args)
        {
            var result = SignatureVerification.validateSignature(File.ReadAllText("/Users/trbe/RiderProjects/NemIDSignatureVerification/NemIDSignatureVerification/opensign_pocesII.xml"));
            Console.WriteLine("Hello: " + result);
            var result2 = SignatureVerification.validateSignature(File.ReadAllText("/Users/trbe/RiderProjects/NemIDSignatureVerification/NemIDSignatureVerification/sample.xml"));
            Console.WriteLine("Hello: " + result2);
        }
    }
}



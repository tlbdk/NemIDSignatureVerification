using System;
using System.IO;
using System.Xml.Linq;
using System.Linq;
using System.Text;
using Newtonsoft.Json;
using Newtonsoft.Json.Serialization;
using System.Security.Cryptography;

namespace NemIDSignatureVerification
{
    public class Program
    {
        public static void Main(string[] args)
        {
            var result = SignatureVerification.validateSignature(File.ReadAllText("/Users/trbe/RiderProjects/NemIDSignatureVerification/NemIDSignatureVerification/opensign_pocesII.xml"));
            Console.WriteLine("opensign_pocesII.xml: " + result);
            var signicatNemidXML = File.ReadAllText("/Users/trbe/RiderProjects/NemIDSignatureVerification/NemIDSignatureVerification/sample.xml");
            var result2 = SignatureVerification.extractValidSignatureRefrences(signicatNemidXML);
            var xdoc = XDocument.Parse(result2[0].OuterXml);
            XNamespace ds_ns = "http://www.w3.org/2000/09/xmldsig#";
            XNamespace openoces_ns = "http://www.openoces.org/2006/07/signature#";


			// Extract and validate signicat payload
			var signicatPayload = xdoc.Root
							   .Element(ds_ns + "SignatureProperties")
							   .Elements(ds_ns + "SignatureProperty")
							   .Where(x => x.Element(openoces_ns + "Name")?.Value == "signicat")
							   .Select(x => x.Element(openoces_ns + "Value")?.Value)
							   .FirstOrDefault();

            // TODO: Validate that the signature was valid at the time of signing
			var payload = new SignicatPayload(signicatPayload);
			var pdfResult = payload.validateAttachment(0, "/Users/trbe/RiderProjects/NemIDSignatureVerification/NemIDSignatureVerification/sample.pdf");
			Console.WriteLine("sample.xml: " + (result2 != null && pdfResult));
        }
    }
}



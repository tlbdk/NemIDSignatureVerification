using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using Newtonsoft.Json;
using Newtonsoft.Json.Serialization;

namespace NemIDSignatureVerification
{
	public class SignicatPayload
	{
		private SHA256 sha256 = SHA256.Create();

		public Attachment[] Attachments { get; set; }
		public SignicatPayload(string base64Payload)
		{
			var jsonBytes = Convert.FromBase64String(base64Payload);
			var json = Encoding.UTF8.GetString(jsonBytes);
			JsonConvert.PopulateObject(json, this, new JsonSerializerSettings()
			{
				ContractResolver = new CamelCasePropertyNamesContractResolver()
			});
		}

		public bool validateAttachment(int index, string path)
		{
			var signicatHash = Convert.FromBase64String(this.Attachments[index].DigestValue);
			using (var file = File.Open(path, FileMode.Open))
			{
				var pdfHash = sha256.ComputeHash(file);
				return signicatHash.SequenceEqual(pdfHash);
			}
		}
	}

	public class Attachment
	{
		public string DigestValue { get; set; }
		public string DocumentDescription { get; set; }
		public string MimeType { get; set; }
		public int SerialNumber { get; set; }
		public DigestMethod DigestMethod { get; set; }
		public string SecondaryDigestValue { get; set; }
		public DigestMethod SecondaryDigestMethod { get; set; }
	}

	public class DigestMethod {
		public String Algorithm { get; set; }
	}
}


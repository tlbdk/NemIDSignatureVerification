using System;
using System.Collections;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Text;
using System.Text.RegularExpressions;
using System.Xml;
using System.Xml.XPath;

namespace NemIDSignatureVerification
{
    public class SignatureVerification
    {
        public static bool validateSignature(string xml)
        {
            var stream = new MemoryStream(Encoding.Default.GetBytes(xml));
            var reader = XmlReader.Create(stream, new XmlReaderSettings
            {
                DtdProcessing = DtdProcessing.Prohibit,
                MaxCharactersFromEntities = 30,
                XmlResolver = null
            });
            var doc = new XmlDocument { PreserveWhitespace = true };
            doc.Load(reader);

            var xmlNamespaces = new XmlNamespaceManager(doc.NameTable);
            xmlNamespaces.AddNamespace("ds", SignedXml.XmlDsigNamespaceUrl);

            var sigElement = (XmlElement) doc.SelectSingleNode("//ds:Signature[1]", xmlNamespaces);
            var signature = new SignedXml(doc);

            signature.LoadXml(sigElement);

            XPathNavigator nav = doc.CreateNavigator();
            nav.MoveToFollowing("SignatureValue", "http://www.w3.org/2000/09/xmldsig#");
            var signatureValue = Regex.Replace(nav.InnerXml.Trim(), @"\s", "");

            byte[] sigVal = Convert.FromBase64String(signatureValue);
            var signedInfo = doc.GetElementsByTagName("ds:SignedInfo")[0];
            var ns = RetrieveNameSpaces((XmlElement) signedInfo);
            InsertNamespacesIntoElement(ns, (XmlElement) signedInfo);
            Stream signedInfoStream = CanonicalizeNode(signedInfo);

            SHA256 sha256 = SHA256.Create();
            byte[] hashedSignedInfo = sha256.ComputeHash(signedInfoStream);

            string oid = CryptoConfig.MapNameToOID("SHA256");

            var Csp = getSignerCertificate(signature).PublicKey.Key as RSACryptoServiceProvider;
            return Csp.VerifyHash(hashedSignedInfo, oid, sigVal);
            
        }

        public static X509Certificate2 getSignerCertificate(SignedXml signature) {
            // Extract all certificates from signature
            var certificates = new Dictionary<string,X509Certificate2>();
            X509Certificate2 signerCertificate = null;
            foreach (var clause in signature.KeyInfo)
            {
                if (!(clause is KeyInfoX509Data)) continue;
                foreach (var x509Cert in ((KeyInfoX509Data)clause).Certificates)
                {
                    X509Certificate2 certificate;
                    if(x509Cert is X509Certificate) {
                        certificate = new X509Certificate2(x509Cert as X509Certificate);

                    } else {
                        certificate = x509Cert as X509Certificate2;
                    }
                    certificates[certificate.Subject] = certificate;

                    Console.WriteLine(certificate.Subject);

                    var keyUsage = (certificate.Extensions["2.5.29.15"] as X509KeyUsageExtension)?.KeyUsages.ToString();
                    if (keyUsage != null && keyUsage.Contains("DigitalSignature") && !keyUsage.Contains("CrlSign")) {
                        signerCertificate = certificate;
                    }
                }
            }

            if(signerCertificate == null) {
                throw new Exception("Did not find signer certificate");
            }

            // TODO: Verify certificate chain
            return signerCertificate;
        }

        public static Hashtable RetrieveNameSpaces(XmlElement xEle)
        {
            Hashtable foundNamespaces = new Hashtable();
            XmlNode currentNode = xEle;

            while (currentNode != null)
            {
                if (currentNode.NodeType == XmlNodeType.Element && !string.IsNullOrEmpty(currentNode.Prefix))
                {
                    if (!foundNamespaces.ContainsKey("xmlns:" + currentNode.Prefix))
                    {
                        foundNamespaces.Add("xmlns:" + currentNode.Prefix, currentNode.NamespaceURI);
                    }
                }

                if (currentNode.Attributes != null && currentNode.Attributes.Count > 0)
                {
                    for (int i = 0; i < currentNode.Attributes.Count; i++)
                    {
                        if (currentNode.Attributes[i].Prefix.Equals("xmlns") || currentNode.Attributes[i].Name.Equals("xmlns"))
                        {
                            if (!foundNamespaces.ContainsKey(currentNode.Attributes[i].Name))
                            {
                                foundNamespaces.Add(currentNode.Attributes[i].Name, currentNode.Attributes[i].Value);
                            }
                        }
                    }
                }
                currentNode = currentNode.ParentNode;
            }
            return foundNamespaces;
        }

        public static void InsertNamespacesIntoElement(Hashtable namespacesHash, XmlElement node)
        {
            XPathNavigator nav = node.CreateNavigator();
            if (string.IsNullOrEmpty(nav.Prefix) && string.IsNullOrEmpty(nav.GetAttribute("xmlns", "")))
            {
                nav.CreateAttribute("", "xmlns", "", nav.NamespaceURI);
            }
            foreach (DictionaryEntry namespacePair in namespacesHash)
            {
                string[] attrName = ((string)namespacePair.Key).Split(':');
                if (attrName.Length > 1 && !node.HasAttribute(attrName[0] + ":" + attrName[1]))
                {
                    nav.CreateAttribute(attrName[0], attrName[1], "", (string)namespacePair.Value);
                }
            }
        }

        public static Stream CanonicalizeNode(XmlNode node)
        {
            XmlNodeReader reader = new XmlNodeReader(node);
            Stream stream = new MemoryStream();
            XmlWriter writer = new XmlTextWriter(stream, Encoding.UTF8);

            writer.WriteNode(reader, false);
            writer.Flush();

            stream.Position = 0;
            XmlDsigC14NTransform transform = new XmlDsigC14NTransform();
            transform.LoadInput(stream);
            return (Stream)transform.GetOutput();
        }
    }
}
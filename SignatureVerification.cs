using System;
using System.Collections;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Text;
using System.Text.RegularExpressions;
using System.Xml;
using System.Linq;

namespace NemIDSignatureVerification
{
    public class SignatureVerification
    {
        public static bool validateSignature(string xml)
        {
            // Load XML Document
            var stream = new MemoryStream(Encoding.Default.GetBytes(xml));
            var reader = XmlReader.Create(stream, new XmlReaderSettings
            {
                DtdProcessing = DtdProcessing.Prohibit,
                MaxCharactersFromEntities = 30,
                XmlResolver = null
            });
            var doc = new XmlDocument { PreserveWhitespace = true };
            doc.Load(reader);

            // Extract signature node
            var xmlNamespaces = new XmlNamespaceManager(doc.NameTable);
            xmlNamespaces.AddNamespace("ds", SignedXml.XmlDsigNamespaceUrl);
            var sigElement = (XmlElement) doc.SelectSingleNode("//ds:Signature[1]", xmlNamespaces);
            var signature = new SignedXml(doc);
            signature.LoadXml(sigElement);

            // Extract signature value for SignedInfo 
            var nav = doc.CreateNavigator();
            nav.MoveToFollowing("SignatureValue", "http://www.w3.org/2000/09/xmldsig#");
            var signatureValue = Regex.Replace(nav.InnerXml.Trim(), @"\s", "");
            var sigVal = Convert.FromBase64String(signatureValue);

            // Extract SignedInfo and hash 
            var signedInfo = doc.GetElementsByTagName("ds:SignedInfo")[0];
            var ns = RetrieveNameSpaces((XmlElement) signedInfo);
            InsertNamespacesIntoElement(ns, (XmlElement) signedInfo);
            var signedInfoStream = CanonicalizeNode(signedInfo);
            var sha256 = SHA256.Create();
            var hashedSignedInfo = sha256.ComputeHash(signedInfoStream);

            // Validate signature for SignedInfo
            try {
                var csp = GetSignerCertificate(signature).PublicKey.Key as RSACryptoServiceProvider;
                var validSignatureValue = csp.VerifyHash(hashedSignedInfo, CryptoConfig.MapNameToOID("SHA256"), sigVal);
                
                return validSignatureValue && AreValidReferences(doc);
            
            } catch (Exception ex) {
                Console.WriteLine(ex.Message);
                return false;
            }
        }

        private static X509Certificate2 GetSignerCertificate(SignedXml signature) {
            // Extract all certificates from signature
            var certificateChain = new X509Chain
            {
                ChainPolicy =
                {
                    RevocationMode = X509RevocationMode.NoCheck,
                    VerificationFlags = X509VerificationFlags.IgnoreWrongUsage,
                    RevocationFlag = X509RevocationFlag.ExcludeRoot
                }
            };
            X509Certificate2 signerCertificate = null;
            foreach (var clause in signature.KeyInfo)
            {
                if (!(clause is KeyInfoX509Data)) continue;
                foreach (var x509Cert in ((KeyInfoX509Data)clause).Certificates)
                {
                    X509Certificate2 certificate;
                    if(x509Cert.GetType() == typeof(X509Certificate)) {
                        certificate = new X509Certificate2((X509Certificate)x509Cert);

                    } else {
                        certificate = x509Cert as X509Certificate2;
                    }

                    var keyUsage = (certificate?.Extensions["2.5.29.15"] as X509KeyUsageExtension)?.KeyUsages.ToString();
                    if (keyUsage != null && keyUsage.Contains("DigitalSignature") && !keyUsage.Contains("CrlSign")) {
                        signerCertificate = certificate;

                    } else if(certificate != null) {
                        certificateChain.ChainPolicy.ExtraStore.Add(certificate);
                    }
                    //Console.WriteLine(certificate.Subject);
                }
            }

            if(signerCertificate == null) {
                throw new Exception("Did not find signer certificate");
            }

            certificateChain.Build(signerCertificate);
            if(certificateChain.ChainStatus.Length > 1) {
                throw new Exception("Certificate chain does not validate, too many errors");
            } 

            var certificateRootChainElement = certificateChain.ChainElements[certificateChain.ChainElements.Count - 1];

            // Only trust nets
            if(certificateRootChainElement.Certificate.Thumbprint != "D6B1F3E9319F68D36F1C71C48E47468130543BCE") {
                throw new Exception("Root certificate does not match Nets");
            }
            
            // If we have a validation error, only allow it to be UntrustedRoot validation becaue the nets certificate is not installed 
            if(certificateChain.ChainStatus.Length != 0 && (certificateChain.ChainStatus[0].Status != X509ChainStatusFlags.UntrustedRoot || certificateRootChainElement.ChainElementStatus[0].Status != X509ChainStatusFlags.UntrustedRoot)) {
                throw new Exception("Certificate chain does not validate: " + certificateChain.ChainStatus[0].StatusInformation);
            }

            return signerCertificate;
        }

        private static bool AreValidReferences(XmlDocument doc)
        {
            var man = new XmlNamespaceManager(doc.NameTable);
            man.AddNamespace("openoces", "http://www.openoces.org/2006/07/signature#");
            man.AddNamespace("ds", "http://www.w3.org/2000/09/xmldsig#");
            var messageReferences = doc.SelectNodes("//openoces:signature/ds:Signature/ds:SignedInfo/ds:Reference", man);
            if (messageReferences == null || messageReferences.Count == 0)
            {
                return false;
            }

            var result = true;
            foreach (XmlNode node in messageReferences)
            {
                result &= IsValidReference(doc ,node);
            }
            return result;
        }

        private static bool IsValidReference(XmlDocument doc ,XmlNode node)
        {
            var elementNav = node.CreateNavigator();
            var elementId = elementNav.GetAttribute("URI", "");
            if (elementId.StartsWith("#"))
            {
                elementId = elementId.Substring(1);
            }

            var referencedNode = RetrieveElementByAttribute(doc, "Id", elementId);
            InsertNamespacesIntoElement(RetrieveNameSpaces((XmlElement)referencedNode.ParentNode), referencedNode);

            var canonicalizedNodeStream = CanonicalizeNode(referencedNode);

            elementNav.MoveToFollowing("DigestMethod", "http://www.w3.org/2000/09/xmldsig#");
            var hashAlg = (HashAlgorithm)CryptoConfig.CreateFromName(elementNav.GetAttribute("Algorithm", ""));
            var hashedNode = hashAlg.ComputeHash(canonicalizedNodeStream);

            elementNav.MoveToFollowing("DigestValue", "http://www.w3.org/2000/09/xmldsig#");
            var digestValue = Convert.FromBase64String(elementNav.InnerXml);

            return hashedNode.SequenceEqual(digestValue);
        }

        private static Hashtable RetrieveNameSpaces(XmlNode xEle)
        {
            var foundNamespaces = new Hashtable();
            var currentNode = xEle;

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
                    for (var i = 0; i < currentNode.Attributes.Count; i++)
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

        private static void InsertNamespacesIntoElement(Hashtable namespacesHash, XmlElement node)
        {
            var nav = node.CreateNavigator();
            if (string.IsNullOrEmpty(nav.Prefix) && string.IsNullOrEmpty(nav.GetAttribute("xmlns", "")))
            {
                nav.CreateAttribute("", "xmlns", "", nav.NamespaceURI);
            }
            foreach (DictionaryEntry namespacePair in namespacesHash)
            {
                var attrName = ((string)namespacePair.Key).Split(':');
                if (attrName.Length > 1 && !node.HasAttribute(attrName[0] + ":" + attrName[1]))
                {
                    nav.CreateAttribute(attrName[0], attrName[1], "", (string)namespacePair.Value);
                }
            }
        }

        private static Stream CanonicalizeNode(XmlNode node)
        {
            var reader = new XmlNodeReader(node);
            Stream stream = new MemoryStream();
            XmlWriter writer = new XmlTextWriter(stream, Encoding.UTF8);

            writer.WriteNode(reader, false);
            writer.Flush();

            stream.Position = 0;
            var transform = new XmlDsigC14NTransform();
            transform.LoadInput(stream);
            return (Stream)transform.GetOutput();
        }

        private static XmlElement RetrieveElementByAttribute(XmlNode xDoc, string attributeName, string attributeValue)
        {
            XmlElement foundElement = null;
            foreach (XmlNode node in xDoc)
            {
                if (node.HasChildNodes)
                {
                    foundElement = RetrieveElementByAttribute(node, attributeName, attributeValue);
                }
                if (foundElement == null && node.Attributes != null && node.Attributes[attributeName] != null && node.Attributes[attributeName].Value.ToLower().Equals(attributeValue.ToLower()))
                {
                    foundElement = (XmlElement)node;
                    break;
                }
                if (foundElement != null)
                {
                    break;
                }
            }
            return foundElement;
        }

        private static void DumpSteam(Stream stream) {
            Console.WriteLine("------");
            var position = stream.Position;
            var streamReader = new StreamReader(stream);
            Console.WriteLine(streamReader.ReadToEnd());
            stream.Seek(position, SeekOrigin.Begin);
            Console.WriteLine("------");
        }
    }
}